"""Per-CA signing algorithm support (CR-0003).

Single source of truth for the `signing_algorithm` token set, its mapping
to `cryptography` hash objects and X.509 OIDs, and the key-type
compatibility matrix. Used by:

- the DB migration that backfills existing CA rows from each cert's
  `signatureAlgorithm` OID,
- API validation at CA creation (`POST /api/ca`,
  `POST /api/ca/generate`) — including the self-signed-only cross-check
  in resolved decision 3,
- the signing pipeline (`KMS.sign_digest`, software / PKCS#11 backends)
  which dispatches mechanisms keyed on the token,
- the dummy-sign step that builds the TBS bytes (certificate, CRL,
  OCSP response, CSR) — the hash object selected here determines the
  `signatureAlgorithm` field embedded in the DER output.

Initial wired set is `rsa-sha256` and `ecdsa-sha256`, matching what
`hsm-support-specs.md §2` documents as supported today. The other
tokens are reserved and rejected with `UnsupportedSigningAlgorithm`
until their backend mechanism rows land.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import SignatureAlgorithmOID


# ── Token constants ──────────────────────────────────────────────────────────

RSA_SHA256 = "rsa-sha256"
RSA_SHA384 = "rsa-sha384"
RSA_SHA512 = "rsa-sha512"
RSA_PSS_SHA256 = "rsa-pss-sha256"
RSA_PSS_SHA384 = "rsa-pss-sha384"
RSA_PSS_SHA512 = "rsa-pss-sha512"
ECDSA_SHA256 = "ecdsa-sha256"
ECDSA_SHA384 = "ecdsa-sha384"
ECDSA_SHA512 = "ecdsa-sha512"
ED25519 = "ed25519"
ED448 = "ed448"


ALL_TOKENS = (
    RSA_SHA256, RSA_SHA384, RSA_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
    ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512,
    ED25519, ED448,
)


# Tokens that are wired through the signing backends today.
#
# RSA PKCS#1 v1.5 and ECDSA share a common shape across SHA-256 / SHA-384
# / SHA-512 — the software backend just swaps the `hashes` instance; the
# PKCS#11 backend swaps the DigestInfo prefix (RSA) or accepts a larger
# digest (ECDSA, `CKM_ECDSA` is hash-agnostic).
#
# Reserved (not yet wired): PSS variants and EdDSA. These reject at
# validation time with `UnsupportedSigningAlgorithm` — PSS needs a
# different builder shape on the dummy-sign step and PSS-specific
# parameters at sign time; EdDSA is prehash-free and needs its own
# builder call.
WIRED_TOKENS = frozenset({
    RSA_SHA256, RSA_SHA384, RSA_SHA512,
    ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512,
})


# ── Errors ───────────────────────────────────────────────────────────────────

class SigningAlgorithmError(ValueError):
    """Base class for `signing_algorithm` validation failures.

    The ``code`` class attribute is the typed error identifier the spec
    requires (CR-0003 validation rules 1–4). It is also embedded as a
    prefix in ``str(self)`` so callers that surface ``description=str(e)``
    via ``flask.abort`` get the typed signal without an extra branch.
    """
    code: str = "signing_algorithm_error"

    def __str__(self) -> str:
        message = super().__str__()
        if message.startswith(self.code + ":"):
            return message
        return f"{self.code}: {message}" if message else self.code


class UnknownSigningAlgorithm(SigningAlgorithmError):
    code = "unknown_signing_algorithm"


class UnsupportedSigningAlgorithm(SigningAlgorithmError):
    """The token is structurally valid but not yet wired in any backend."""
    code = "unsupported_signing_algorithm"


class SigningAlgorithmKeyMismatch(SigningAlgorithmError):
    code = "signing_algorithm_key_mismatch"


class SigningAlgorithmCertMismatch(SigningAlgorithmError):
    code = "signing_algorithm_cert_mismatch"


# ── Token ↔ OID mapping (for backfill + self-signed cert cross-check) ────────

# Forward map: token → x509 OID. PSS shares one OID for the whole family
# (parameters distinguish the hash); EdDSA has dedicated OIDs.
_TOKEN_TO_OID = {
    RSA_SHA256: SignatureAlgorithmOID.RSA_WITH_SHA256,
    RSA_SHA384: SignatureAlgorithmOID.RSA_WITH_SHA384,
    RSA_SHA512: SignatureAlgorithmOID.RSA_WITH_SHA512,
    ECDSA_SHA256: SignatureAlgorithmOID.ECDSA_WITH_SHA256,
    ECDSA_SHA384: SignatureAlgorithmOID.ECDSA_WITH_SHA384,
    ECDSA_SHA512: SignatureAlgorithmOID.ECDSA_WITH_SHA512,
    ED25519: SignatureAlgorithmOID.ED25519,
    ED448: SignatureAlgorithmOID.ED448,
}


def token_to_oid_dotted(token: str) -> str:
    """Return the dotted-OID string for *token*, or raise."""
    if token not in _TOKEN_TO_OID:
        raise UnknownSigningAlgorithm(
            f"No OID mapping for signing_algorithm token: {token!r}"
        )
    return _TOKEN_TO_OID[token].dotted_string


# Reverse map: cert.signature_algorithm_oid.dotted_string → token. PSS is
# handled separately because its OID does not distinguish the hash; the
# caller must inspect cert.signature_algorithm_parameters to disambiguate.
_OID_TO_TOKEN = {oid.dotted_string: token for token, oid in _TOKEN_TO_OID.items()}


def oid_to_token(dotted_oid: str, *, pss_hash: str | None = None) -> str:
    """Map an X.509 `signatureAlgorithm` OID (and PSS hash, if PSS) to a token.

    Raises `UnknownSigningAlgorithm` if the OID is not in the supported set.
    For PSS (OID 1.2.840.113549.1.1.10), `pss_hash` must be one of
    'sha256' | 'sha384' | 'sha512' — extracted from
    `cert.signature_algorithm_parameters.algorithm` by the caller.
    """
    if dotted_oid == "1.2.840.113549.1.1.10":  # id-RSASSA-PSS
        if pss_hash is None:
            raise UnknownSigningAlgorithm(
                "PSS OID requires the parameter hash to disambiguate; "
                "pass pss_hash='sha256'|'sha384'|'sha512'"
            )
        mapping = {
            "sha256": RSA_PSS_SHA256,
            "sha384": RSA_PSS_SHA384,
            "sha512": RSA_PSS_SHA512,
        }
        if pss_hash not in mapping:
            raise UnknownSigningAlgorithm(
                f"Unsupported PSS hash: {pss_hash!r}"
            )
        return mapping[pss_hash]
    token = _OID_TO_TOKEN.get(dotted_oid)
    if token is None:
        raise UnknownSigningAlgorithm(
            f"No signing_algorithm token for OID {dotted_oid!r}"
        )
    return token


def token_from_certificate(cert) -> str:
    """Derive the signing_algorithm token from a `cryptography` x509.Certificate.

    Inspects `cert.signature_algorithm_oid` (and, for PSS, the hash carried
    in `signature_algorithm_parameters`). Raises `UnknownSigningAlgorithm`
    if the cert was signed with an algorithm outside the supported set.
    """
    oid = cert.signature_algorithm_oid.dotted_string
    if oid == "1.2.840.113549.1.1.10":
        params = cert.signature_algorithm_parameters
        # `cryptography` returns a `padding.PSS` instance whose
        # `_mgf._algorithm` (and `_algorithm` on newer versions) is the
        # hash. Use the public `.algorithm` attribute when available.
        hash_alg = getattr(params, "_algorithm", None) or getattr(params, "algorithm", None)
        if hash_alg is None:
            raise UnknownSigningAlgorithm(
                "PSS certificate has no inspectable hash parameter"
            )
        name = hash_alg.name.lower()  # "sha256" / "sha384" / "sha512"
        return oid_to_token(oid, pss_hash=name)
    return oid_to_token(oid)


# ── Key-type compatibility table ─────────────────────────────────────────────

_RSA_TOKENS = frozenset({
    RSA_SHA256, RSA_SHA384, RSA_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
})
_ECDSA_TOKENS_BY_CURVE = {
    "P-256": frozenset({ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512}),
    "P-384": frozenset({ECDSA_SHA384, ECDSA_SHA512}),
    "P-521": frozenset({ECDSA_SHA512}),
}


def _normalize_curve_name(curve_name: str) -> str:
    """Map cryptography's curve names ('secp256r1') to spec tokens ('P-256').

    `KeyStorage.key_type` uses the 'ECDSA-secp256r1' form (per
    db.insert_ca which builds it as `f"ECDSA-{curve.name}"`). The spec's
    `ECDSA-P-256` / `P-384` / `P-521` are aliases the UI surfaces.
    """
    aliases = {
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
        "prime256v1": "P-256",
    }
    return aliases.get(curve_name, curve_name)


def tokens_for_public_key(public_key) -> frozenset[str]:
    """Return the set of `signing_algorithm` tokens compatible with *public_key*.

    Used to validate at API time (key-type compatibility check, resolved
    decision per §17.3) and to populate the UI dropdown.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return _RSA_TOKENS
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = _normalize_curve_name(public_key.curve.name)
        return _ECDSA_TOKENS_BY_CURVE.get(curve, frozenset())
    # Ed25519 / Ed448 are matched by exact key-class match, not via a
    # compatibility set with multiple options.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    except ImportError:  # pragma: no cover — defensive
        return frozenset()
    if isinstance(public_key, Ed25519PublicKey):
        return frozenset({ED25519})
    if isinstance(public_key, Ed448PublicKey):
        return frozenset({ED448})
    return frozenset()


def tokens_for_key_type(key_type: str) -> frozenset[str]:
    """Same as `tokens_for_public_key`, but driven by `KeyStorage.key_type`.

    Used when a public key object isn't immediately at hand (e.g. UI
    pre-filtering by selected provider key, or the CR-0001 generate
    flow before the new key is created).
    """
    if not key_type:
        return frozenset()
    upper = key_type.upper()
    if upper.startswith("RSA-"):
        return _RSA_TOKENS
    if upper.startswith("ECDSA-"):
        curve = key_type.split("-", 1)[1]
        return _ECDSA_TOKENS_BY_CURVE.get(_normalize_curve_name(curve), frozenset())
    if upper == "ED25519":
        return frozenset({ED25519})
    if upper == "ED448":
        return frozenset({ED448})
    return frozenset()


# ── Hash object dispatch (for dummy-sign builder calls) ──────────────────────

# The `cryptography` builder API needs an explicit hash object for the
# dummy-sign step so the right `signatureAlgorithm` OID ends up in the TBS.
# EdDSA passes `None` (it's prehash-free); PSS would require a different
# builder shape — not wired yet (raises `UnsupportedSigningAlgorithm`).
_TOKEN_TO_HASH = {
    RSA_SHA256: hashes.SHA256,
    RSA_SHA384: hashes.SHA384,
    RSA_SHA512: hashes.SHA512,
    ECDSA_SHA256: hashes.SHA256,
    ECDSA_SHA384: hashes.SHA384,
    ECDSA_SHA512: hashes.SHA512,
}


def hash_for_token(token: str):
    """Return a fresh `cryptography` hash instance for the token.

    Used both for the dummy-sign builder call (so the embedded
    `signatureAlgorithm` OID matches) and for hashing the TBS bytes
    before they go to the KMS.

    For tokens not wired in any signing backend today
    (`rsa-pss-*`, `ed25519`, `ed448`), raises `UnsupportedSigningAlgorithm`.
    """
    if token not in _TOKEN_TO_HASH:
        if token in ALL_TOKENS:
            raise UnsupportedSigningAlgorithm(
                f"signing_algorithm {token!r} is reserved but not yet supported "
                "by any signing backend"
            )
        raise UnknownSigningAlgorithm(f"Unknown signing_algorithm: {token!r}")
    return _TOKEN_TO_HASH[token]()


def is_ecdsa_token(token: str) -> bool:
    return token in (ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512)


def is_rsa_pkcs1_token(token: str) -> bool:
    return token in (RSA_SHA256, RSA_SHA384, RSA_SHA512)


# ── Default selection (UI dropdown, resolved decision 4) ─────────────────────

def default_token_for_public_key(public_key) -> str | None:
    """Return the SHA-256 variant matching *public_key*'s family, or None.

    This is the UI default per resolved decision 4 of CR-0003. The API
    still requires `signing_algorithm` to be supplied explicitly — this
    helper exists only for the UI dropdown and the migration backfill
    fallback.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return RSA_SHA256
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ECDSA_SHA256
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    except ImportError:  # pragma: no cover
        return None
    if isinstance(public_key, Ed25519PublicKey):
        return ED25519
    if isinstance(public_key, Ed448PublicKey):
        return ED448
    return None


def default_token_for_key_type(key_type: str) -> str | None:
    """Same as `default_token_for_public_key`, keyed on `KeyStorage.key_type`."""
    if not key_type:
        return None
    upper = key_type.upper()
    if upper.startswith("RSA-"):
        return RSA_SHA256
    if upper.startswith("ECDSA-"):
        return ECDSA_SHA256
    if upper == "ED25519":
        return ED25519
    if upper == "ED448":
        return ED448
    return None


# ── High-level validation entry point ────────────────────────────────────────

def validate_for_creation(
    token: str,
    *,
    public_key,
    certificate=None,
    enforce_cert_match: bool = False,
) -> str:
    """Run the full §17.3 validation pipeline against a CA-creation request.

    Parameters:
        token: the operator-supplied `signing_algorithm` value.
        public_key: the bound key's public key (`cryptography` object).
        certificate: when supplied, an x509.Certificate whose
            `signatureAlgorithm` is consulted iff `enforce_cert_match`.
        enforce_cert_match: True for self-signed imports per resolved
            decision 3. False for intermediate-CA imports and the
            in-app generate flow.

    Returns the validated, normalised token (lower-cased). Raises a
    `SigningAlgorithmError` subclass otherwise — the route layer maps
    these to HTTP 400 with the typed `code` payload.

    Backend-mechanism availability is also enforced here (any reserved
    token outside `WIRED_TOKENS` raises `UnsupportedSigningAlgorithm`).
    Doing the check here keeps the route layer free of token-set
    knowledge.
    """
    if token is None or not isinstance(token, str):
        raise UnknownSigningAlgorithm(
            "signing_algorithm is required and must be a string"
        )
    normalised = token.strip().lower()
    if normalised not in ALL_TOKENS:
        raise UnknownSigningAlgorithm(
            f"signing_algorithm {token!r} is not in the supported token set"
        )

    compatible = tokens_for_public_key(public_key)
    if normalised not in compatible:
        raise SigningAlgorithmKeyMismatch(
            f"signing_algorithm {normalised!r} is not compatible with the "
            f"bound key (compatible tokens: {sorted(compatible) or 'none'})"
        )

    if normalised not in WIRED_TOKENS:
        raise UnsupportedSigningAlgorithm(
            f"signing_algorithm {normalised!r} is structurally valid but "
            "not yet wired in any signing backend"
        )

    if enforce_cert_match:
        if certificate is None:
            raise SigningAlgorithmCertMismatch(
                "Cannot enforce cert match without a certificate"
            )
        try:
            cert_token = token_from_certificate(certificate)
        except UnknownSigningAlgorithm as e:
            raise SigningAlgorithmCertMismatch(
                f"Certificate's signatureAlgorithm does not map to any "
                f"supported token: {e}"
            ) from e
        if cert_token != normalised:
            raise SigningAlgorithmCertMismatch(
                f"signing_algorithm {normalised!r} does not match the "
                f"self-signed certificate's signatureAlgorithm ({cert_token!r})"
            )

    return normalised


def is_self_signed(certificate) -> bool:
    """Cheap subject==issuer check used to decide whether decision-3 applies."""
    return certificate.subject == certificate.issuer


# ── Hash-family helpers (used for OCSP responder algorithm derivation) ───────

_TOKEN_TO_HASH_NAME = {
    RSA_SHA256: "sha256", RSA_SHA384: "sha384", RSA_SHA512: "sha512",
    RSA_PSS_SHA256: "sha256", RSA_PSS_SHA384: "sha384", RSA_PSS_SHA512: "sha512",
    ECDSA_SHA256: "sha256", ECDSA_SHA384: "sha384", ECDSA_SHA512: "sha512",
    ED25519: "ed25519", ED448: "ed448",
}


def hash_family_of(token: str) -> str:
    """Return the canonical hash-family name for a token."""
    if token not in _TOKEN_TO_HASH_NAME:
        raise UnknownSigningAlgorithm(f"Unknown signing_algorithm: {token!r}")
    return _TOKEN_TO_HASH_NAME[token]


def derive_responder_token(ca_token: str, responder_public_key) -> str:
    """Pick the OCSP responder's signing token per CR-0003 decision 5.

    Decision 5 says the responder reuses the parent CA's
    `signing_algorithm`. Literal reuse works only when the responder's
    key is the same family as the CA's. When the families differ
    (e.g. RSA CA + ECDSA responder) we keep the *hash family* from the
    CA and pair it with the responder's *key family*, producing a
    structurally analogous token. For today's wired set
    (`rsa-sha256` / `ecdsa-sha256`) this is automatic — both use
    SHA-256. For SHA-384+ this lands once the backend mechanism row
    lands.

    Raises `SigningAlgorithmKeyMismatch` if no compatible token exists
    for the responder key (e.g. CA token implies a hash size the
    responder's key family doesn't support).
    """
    family = hash_family_of(ca_token)
    compatible = tokens_for_public_key(responder_public_key)
    if not compatible:
        raise SigningAlgorithmKeyMismatch(
            f"Responder key {type(responder_public_key).__name__} has no "
            "compatible signing_algorithm token"
        )
    for token in compatible:
        if _TOKEN_TO_HASH_NAME.get(token) == family:
            return token
    raise SigningAlgorithmKeyMismatch(
        f"Responder key {type(responder_public_key).__name__} has no token "
        f"matching CA hash family {family!r} (CA token: {ca_token!r}); "
        "rekey the responder to match the CA's algorithm family, or add "
        "an override column on OCSPResponders"
    )
