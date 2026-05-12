"""
PKCS11Backend — sign with keys resident on a PKCS#11 token.

The backend owns a single :class:`PKCS11Helper` session for the lifetime
of a provider activation: ``open()`` creates the session and logs in;
``load_key()`` re-uses it to find an on-token object handle by CKA_ID;
``sign_digest()`` signs through it; ``close()`` closes it. This closes
Gap 6 (one session per provider, not per cached key) from
:doc:`../../doc/hsm-support-specs.md`.

A per-backend reentrant lock serialises ``load_key`` / ``sign_digest`` /
``close`` because PKCS#11 sessions are not thread-safe by spec —
concurrent ``C_Sign`` calls on the same session are undefined behaviour
across vendors.

On ``CKR_SESSION_HANDLE_INVALID`` / ``CKR_DEVICE_REMOVED``, sign_digest
attempts a single reconnect (close session, reopen, re-find the on-token
object) before propagating. Anything else propagates immediately.
"""
from __future__ import annotations

import os
import threading
from collections import namedtuple

import PyKCS11
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..log import logger
from ..pkcs11_helper import PKCS11Helper
from .base import BackendNotActive, KeyHandle


# Conservative PKCS#11 subset (kms-specs.md §8.1).
_RSA_BIT_SIZES = {2048, 3072, 4096}

# Named-curve OIDs (DER-encoded ASN.1 OBJECT IDENTIFIER) for CKA_EC_PARAMS.
_EC_PARAMS_DER = {
    "P-256": bytes.fromhex("06082A8648CE3D030107"),  # secp256r1
    "P-384": bytes.fromhex("06052B81040022"),         # secp384r1
}


# What the backend caches in ``KeyHandle._state`` for PKCS#11 keys. The
# token_object handle is invalidated by a session reset, so reconnect
# logic re-resolves it via ``cka_id``.
class _Pkcs11KeyState:
    __slots__ = ("cka_id", "cka_key_type", "token_object")

    def __init__(self, cka_id: str, cka_key_type: int, token_object):
        self.cka_id = cka_id
        self.cka_key_type = cka_key_type
        self.token_object = token_object


# RFC 8017 §9.2 — DigestInfo prefix that PKCS#1 v1.5 SHA-256 signatures
# carry before the digest. Identical to the constant in pypki/key_tools.py;
# duplicated here to keep the backend self-contained.
_SHA256_RSA_PKCS_DIGESTINFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


class PKCS11Backend:
    """PKCS#11 signing backend. See :class:`CryptoBackend`."""

    def __init__(self):
        self._provider: dict | None = None
        self._helper: PKCS11Helper | None = None
        # Cached PIN bytes when the backend was opened with secret_override
        # (operator-prompt activation). Needed so _reconnect can reopen the
        # session without going back to a resolver that doesn't have the PIN.
        # Scrubbed on close().
        self._cached_secret: bytes | None = None
        self._lock = threading.RLock()

    # ── lifecycle ────────────────────────────────────────────────────────────

    def open(self, provider: dict, secret_override: bytes = None) -> None:
        with self._lock:
            if self._helper is not None:
                return  # already active

            from ..key_encryption import resolve_provider_secret, KEKUnavailable
            try:
                if secret_override is not None:
                    if not isinstance(secret_override, (bytes, bytearray)) or not secret_override:
                        raise ValueError("secret_override must be non-empty bytes")
                    pin = bytes(secret_override).decode("utf-8")
                else:
                    pin_bytes = resolve_provider_secret(provider)
                    pin = pin_bytes.decode("utf-8")
            except KEKUnavailable as e:
                raise BackendNotActive(
                    f"PKCS11Backend: cannot resolve PIN for provider "
                    f"id={provider.get('id')} ('{provider.get('label')}'): {e}"
                ) from e
            except NotImplementedError as e:
                raise BackendNotActive(
                    f"PKCS11Backend: provider id={provider.get('id')} uses an "
                    f"unsupported auth_secret_ref kind: {e}"
                ) from e

            module_path = provider.get("module_path")
            slot_label = provider.get("slot_label")
            try:
                helper = PKCS11Helper(lib_path=module_path) if module_path else PKCS11Helper()
                helper.open_session(pin, slot_label=slot_label)
            except Exception as e:
                raise BackendNotActive(
                    f"PKCS11Backend: failed to open session for provider "
                    f"id={provider.get('id')} ('{provider.get('label')}'): {e}"
                ) from e

            self._helper = helper
            self._provider = provider
            self._cached_secret = bytes(secret_override) if secret_override is not None else None
            logger.info(
                f"PKCS11Backend: activated provider id={provider.get('id')} "
                f"('{provider.get('label')}') module={module_path} "
                f"slot_label={slot_label}"
                + (" [operator-supplied PIN]" if secret_override is not None else "")
            )

    def close(self) -> None:
        with self._lock:
            if self._helper is None:
                return
            try:
                self._helper.close_session()
            except Exception:
                logger.exception(
                    f"PKCS11Backend: close_session failed for provider "
                    f"id={self._provider.get('id') if self._provider else '?'}"
                )
            provider = self._provider
            self._helper = None
            self._provider = None
            self._cached_secret = None
            if provider is not None:
                logger.info(
                    f"PKCS11Backend: deactivated provider id={provider.get('id')} "
                    f"('{provider.get('label')}')"
                )

    def is_active(self) -> bool:
        return self._helper is not None

    # ── key operations ───────────────────────────────────────────────────────

    def load_key(self, record: dict) -> KeyHandle:
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.load_key: backend is not open")
            cka_id = record.get("hsm_token_id")
            if not cka_id:
                raise ValueError(
                    f"PKCS11Backend.load_key: KeyStorage id={record.get('id')} "
                    f"has no hsm_token_id"
                )
            cka_id_bytes = _validate_cka_id_hex(cka_id, key_id=record.get("id"))
            token_object = self._find_private_by_id(cka_id_bytes)
            session = self._helper.get_session()
            cka_key_type = session.getAttributeValue(
                token_object, [PyKCS11.CKA_KEY_TYPE]
            )[0]
            return KeyHandle(
                key_id=record.get("id"),
                provider_id=self._provider["id"],
                state=_Pkcs11KeyState(
                    cka_id=cka_id,
                    cka_key_type=cka_key_type,
                    token_object=token_object,
                ),
            )

    def unload_key(self, handle: KeyHandle) -> None:
        # Provider-scoped session; nothing per-key to release.
        return

    # ── Generation / inspection / deletion (Phase 5a) ─────────────────────────

    def generate_key(self, key_type: str, label: str, hsm_token_id: bytes = None) -> dict:
        """
        Generate a keypair on the token. Enforces the mandatory CKA_*
        attribute set from kms-specs.md §8.2 — Luna rejects keys that
        omit these and SoftHSM2 silently accepts weaker combinations, so
        this is the boundary that keeps SoftHSM-tested code portable.

        Returns a dict the KMS uses to persist a ``KeyStorage`` row::

            {
                "storage_type":  "HSM",
                "hsm_token_id":  <hex CKA_ID>,
                "public_key":    <PEM str>,
                "key_type":      <normalised label>,
                "label":         <provided label>,
            }
        """
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.generate_key: backend is not open")
            session = self._helper.get_session()

            # CKA_ID for the new objects — caller-supplied or random 8 bytes.
            cka_id = bytes(hsm_token_id) if hsm_token_id else os.urandom(8)
            cka_id_hex = cka_id.hex()

            kt = (key_type or "").strip()
            normalised, mech, pub_template_extra, priv_template_extra = _resolve_pkcs11_key_type(kt)

            common = [
                (PyKCS11.CKA_LABEL, label or f"pypki-{cka_id_hex}"),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_ID, cka_id),
            ]
            # Mandatory public-key attributes (kms-specs.md §8.2).
            pub_template = common + [
                (PyKCS11.CKA_VERIFY, True),
                (PyKCS11.CKA_ENCRYPT, False),
            ] + pub_template_extra
            # Mandatory private-key attributes.
            priv_template = common + [
                (PyKCS11.CKA_PRIVATE, True),
                (PyKCS11.CKA_SENSITIVE, True),
                (PyKCS11.CKA_EXTRACTABLE, False),
                (PyKCS11.CKA_SIGN, True),
                (PyKCS11.CKA_DECRYPT, False),
            ] + priv_template_extra

            try:
                pub_handle, priv_handle = session.generateKeyPair(
                    pub_template, priv_template, mech,
                )
            except PyKCS11.PyKCS11Error as e:
                raise RuntimeError(
                    f"PKCS11Backend.generate_key: token rejected key generation: {e}"
                ) from e

            # Build PEM SubjectPublicKeyInfo for KeyStorage.public_key.
            public_pem = _read_public_key_pem(session, pub_handle, normalised)

            logger.info(
                f"PKCS11Backend: generated {normalised} on provider "
                f"id={self._provider.get('id')} (CKA_ID={cka_id_hex}, label={label!r})"
            )
            return {
                "storage_type": "HSM",
                "hsm_token_id": cka_id_hex,
                "public_key": public_pem,
                "key_type": normalised,
                "label": label,
            }

    def _find_private_by_id(self, cka_id_bytes: bytes):
        """Locate the private-key object on the open session by raw CKA_ID
        bytes. Raises RuntimeError if not found. Caller must hold ``self._lock``."""
        session = self._helper.get_session()
        priv_keys = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_ID, cka_id_bytes),
        ])
        if not priv_keys:
            raise RuntimeError(
                f"PKCS11Backend: private key with CKA_ID={cka_id_bytes.hex()} "
                f"not found on provider id={self._provider.get('id')}"
            )
        return priv_keys[0]

    def find_key_by_id(self, hsm_token_id: str) -> dict | None:
        """
        Locate an existing on-token keypair by its hex CKA_ID and return
        the metadata pyPKI needs to register it. The CKA_ID identifies a
        *pair* — both the private key and its matching public key carry
        the same CKA_ID per PKCS#11 convention — and importing the pair
        produces a single ``KeyStorage`` row.

        Returns ``None`` if no private-key object with that CKA_ID exists,
        or a dict::

            {
                "hsm_token_id": <hex CKA_ID>,
                "public_key":   <PEM SubjectPublicKeyInfo str>,
                "key_type":     <normalised label, e.g. "RSA-2048">,
                "cka_label":    <CKA_LABEL on the private key, or None>,
            }
        """
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.find_key_by_id: backend is not open")
            session = self._helper.get_session()
            try:
                cka_id_bytes = _validate_cka_id_hex(hsm_token_id)
            except ValueError:
                return None
            try:
                priv_handle = self._find_private_by_id(cka_id_bytes)
            except RuntimeError:
                return None
            cka_key_type = session.getAttributeValue(priv_handle, [PyKCS11.CKA_KEY_TYPE])[0]
            normalised = _normalise_key_type_from_token(session, priv_handle, cka_key_type)
            cka_label = _read_cka_label(session, priv_handle)
            # Find the matching public key (same CKA_ID) for the SPKI.
            pub_objs = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_ID, cka_id_bytes),
            ])
            if not pub_objs:
                raise RuntimeError(
                    f"PKCS11Backend.find_key_by_id: private key {hsm_token_id} found "
                    f"but no matching public key on the token"
                )
            public_pem = _read_public_key_pem(session, pub_objs[0], normalised)
            # Fall back to the public key's label if the private one is empty.
            if not cka_label:
                cka_label = _read_cka_label(session, pub_objs[0])
            return {
                "hsm_token_id": hsm_token_id,
                "public_key": public_pem,
                "key_type": normalised,
                "cka_label": cka_label,
            }

    def delete_key(self, hsm_token_id: str) -> None:
        """
        Remove both the private and public on-token objects with the
        given hex CKA_ID. Used by ``KMS.delete_key`` for HSM rows.
        """
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.delete_key: backend is not open")
            session = self._helper.get_session()
            cka_id_bytes = _validate_cka_id_hex(hsm_token_id)
            for obj_class in (PyKCS11.CKO_PRIVATE_KEY, PyKCS11.CKO_PUBLIC_KEY):
                objs = session.findObjects([
                    (PyKCS11.CKA_CLASS, obj_class),
                    (PyKCS11.CKA_ID, cka_id_bytes),
                ])
                for o in objs:
                    try:
                        session.destroyObject(o)
                    except PyKCS11.PyKCS11Error as e:
                        logger.warning(
                            f"PKCS11Backend.delete_key: destroyObject failed "
                            f"(CKA_ID={hsm_token_id}, class={obj_class}): {e}"
                        )

    def sign_digest(self, handle: KeyHandle, tbs_digest: bytes) -> bytes:
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.sign_digest: backend is not open")
            try:
                return self._sign_with_state(handle._state, tbs_digest)
            except PyKCS11.PyKCS11Error as e:
                if int(e.value) not in (
                    int(PyKCS11.CKR_SESSION_HANDLE_INVALID),
                    int(PyKCS11.CKR_DEVICE_REMOVED),
                ):
                    raise
                logger.warning(
                    f"PKCS11Backend: session invalidated ({e}); attempting one reconnect "
                    f"for provider id={self._provider.get('id')}"
                )
                self._reconnect()
                # The new session has a different CK_OBJECT_HANDLE for the same
                # on-token object; re-find it by CKA_ID.
                cka_id_bytes = _validate_cka_id_hex(handle._state.cka_id)
                handle._state.token_object = self._find_private_by_id(cka_id_bytes)
                return self._sign_with_state(handle._state, tbs_digest)

    # ── internal helpers ─────────────────────────────────────────────────────

    def _sign_with_state(self, state: _Pkcs11KeyState, tbs_digest: bytes) -> bytes:
        """Run the actual sign call. Caller must hold ``self._lock``."""
        session = self._helper.get_session()

        if state.cka_key_type == PyKCS11.CKK_RSA:
            # RSA PKCS#1 v1.5 — prepend SHA-256 DigestInfo so CKM_RSA_PKCS
            # produces a verifiable signature (Gap 1 fix; see key_tools.py).
            if len(tbs_digest) != 32:
                raise ValueError(
                    f"PKCS11Backend: RSA sign expects a 32-byte SHA-256 digest, "
                    f"got {len(tbs_digest)} bytes"
                )
            payload = _SHA256_RSA_PKCS_DIGESTINFO + tbs_digest
            mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            return bytes(session.sign(state.token_object, payload, mech))

        if state.cka_key_type == PyKCS11.CKK_EC:
            # ECDSA — token returns raw r || s; encode as DER SEQUENCE
            # (Gap 2 fix; matches what the software backend produces).
            mech = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)
            raw = bytes(session.sign(state.token_object, tbs_digest, mech))
            if not raw or len(raw) % 2 != 0:
                raise ValueError(
                    f"PKCS11Backend: ECDSA raw signature has unexpected length: {len(raw)}"
                )
            half = len(raw) // 2
            r = int.from_bytes(raw[:half], "big")
            s = int.from_bytes(raw[half:], "big")
            return encode_dss_signature(r, s)

        raise ValueError(
            f"PKCS11Backend: unsupported CKA_KEY_TYPE on HSM key: {state.cka_key_type}"
        )

    def _reconnect(self) -> None:
        """Close the current session and open a fresh one against the same
        provider. Caller must hold ``self._lock``. Raises
        :class:`BackendNotActive` if the backend was never opened."""
        if self._helper is None or self._provider is None:
            raise BackendNotActive("PKCS11Backend._reconnect: backend is not open")

        try:
            self._helper.close_session()
        except Exception:
            # Best-effort; if the underlying session is already gone the
            # close itself can fail. We will reopen anyway.
            pass

        from ..key_encryption import resolve_provider_secret
        if self._cached_secret is not None:
            pin = self._cached_secret.decode("utf-8")
        else:
            pin = resolve_provider_secret(self._provider).decode("utf-8")
        slot_label = self._provider.get("slot_label")
        self._helper.open_session(pin, slot_label=slot_label)
        logger.info(
            f"PKCS11Backend: reconnected provider id={self._provider.get('id')} "
            f"('{self._provider.get('label')}')"
        )


# ── Module-level helpers for key generation / inspection ──────────────────────

def _resolve_pkcs11_key_type(key_type: str):
    """
    Map a canonical key-type label to the tuple
    ``(normalised_label, mechanism, public_template_extra, private_template_extra)``
    used by ``PKCS11Backend.generate_key``. Restricted to the conservative
    subset shared with all targeted HSM vendors.
    """
    kt = (key_type or "").strip()
    upper = kt.upper()

    if upper.startswith("RSA"):
        suffix = upper.replace("RSA-", "").replace("RSA", "")
        try:
            bits = int(suffix)
        except ValueError:
            raise ValueError(f"Invalid RSA key_type {key_type!r}")
        if bits not in _RSA_BIT_SIZES:
            raise ValueError(
                f"Invalid RSA size {bits}; choose from {sorted(_RSA_BIT_SIZES)}"
            )
        mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN, None)
        pub_extra = [(PyKCS11.CKA_MODULUS_BITS, bits)]
        priv_extra = []
        return f"RSA-{bits}", mech, pub_extra, priv_extra

    if upper.startswith("ECDSA"):
        suffix = upper[len("ECDSA"):].lstrip("-")
        normalised = (
            "P-256" if "256" in suffix else
            "P-384" if "384" in suffix else
            None
        )
        if normalised not in _EC_PARAMS_DER:
            raise ValueError(
                f"Invalid ECDSA curve {key_type!r}; choose from {list(_EC_PARAMS_DER)}"
            )
        mech = PyKCS11.Mechanism(PyKCS11.CKM_EC_KEY_PAIR_GEN, None)
        pub_extra = [(PyKCS11.CKA_EC_PARAMS, _EC_PARAMS_DER[normalised])]
        priv_extra = []
        return f"ECDSA-{normalised}", mech, pub_extra, priv_extra

    raise ValueError(
        f"Unsupported key_type {key_type!r}. Choose from: "
        f"RSA-2048, RSA-3072, RSA-4096, ECDSA-P-256, ECDSA-P-384."
    )


def _validate_cka_id_hex(cka_id, key_id=None) -> bytes:
    """
    Validate that ``cka_id`` is a non-empty hex string with an even length
    and decode it to raw bytes. Closes Gap 9 — pre-Phase-6 the value flowed
    through to ``bytes.fromhex`` at sign time, so a typo produced a confusing
    PKCS#11 error on first use rather than a clear validation failure at
    insert / import / load.
    """
    if not isinstance(cka_id, str) or not cka_id:
        raise ValueError(
            f"hsm_token_id must be a non-empty hex string"
            + (f" (key_id={key_id})" if key_id is not None else "")
        )
    if len(cka_id) % 2 != 0:
        raise ValueError(
            f"hsm_token_id has odd length {len(cka_id)}; expected an even number of hex digits"
            + (f" (key_id={key_id}, value={cka_id!r})" if key_id is not None else "")
        )
    try:
        return bytes.fromhex(cka_id)
    except ValueError as e:
        raise ValueError(
            f"hsm_token_id is not valid hex: {e}"
            + (f" (key_id={key_id}, value={cka_id!r})" if key_id is not None else "")
        ) from e


def _read_cka_label(session, handle) -> str | None:
    """Read CKA_LABEL off a token object and return a clean string, or None.
    PyKCS11 returns the label as ``str``, ``bytes``, or a list-of-ints
    depending on the underlying token; normalise to a stripped str."""
    try:
        raw = session.getAttributeValue(handle, [PyKCS11.CKA_LABEL])[0]
    except PyKCS11.PyKCS11Error:
        return None
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8", "replace")
    elif isinstance(raw, list):
        # PyKCS11 sometimes returns a list of CK_BYTE values.
        try:
            text = bytes(raw).decode("utf-8", "replace")
        except Exception:
            return None
    else:
        text = str(raw)
    text = text.strip().rstrip("\x00").strip()
    return text or None


def _normalise_key_type_from_token(session, key_handle, cka_key_type) -> str:
    """Read on-token attributes and produce a canonical key_type label.

    Works on either a private or a public key handle. Note that
    ``CKA_MODULUS_BITS`` is part of the *public* key template in PKCS#11,
    and SoftHSM2 doesn't expose it on private keys, so this function
    derives the bit length from ``CKA_MODULUS`` instead.
    """
    if cka_key_type == PyKCS11.CKK_RSA:
        modulus_attr = session.getAttributeValue(key_handle, [PyKCS11.CKA_MODULUS])[0]
        if modulus_attr is None:
            # Fallback: try CKA_MODULUS_BITS (set on public-key handles).
            mb = session.getAttributeValue(key_handle, [PyKCS11.CKA_MODULUS_BITS])[0]
            if mb is None:
                raise ValueError(
                    "Cannot determine RSA key size: neither CKA_MODULUS nor "
                    "CKA_MODULUS_BITS was readable on this handle"
                )
            return f"RSA-{int(mb)}"
        bits = len(bytes(modulus_attr)) * 8
        return f"RSA-{bits}"
    if cka_key_type == PyKCS11.CKK_EC:
        ec_params = bytes(session.getAttributeValue(key_handle, [PyKCS11.CKA_EC_PARAMS])[0])
        for name, der in _EC_PARAMS_DER.items():
            if ec_params == der:
                return f"ECDSA-{name}"
        return "ECDSA-unknown"
    raise ValueError(f"Unsupported CKA_KEY_TYPE on token: {cka_key_type}")


def _read_public_key_pem(session, pub_handle, normalised: str) -> str:
    """Read a public-key object off the token and return PEM
    SubjectPublicKeyInfo for storage in ``KeyStorage.public_key``."""
    if normalised.startswith("RSA-"):
        modulus, exponent = session.getAttributeValue(
            pub_handle, [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT]
        )
        n = int.from_bytes(bytes(modulus), "big")
        e = int.from_bytes(bytes(exponent), "big")
        pubkey = rsa.RSAPublicNumbers(e=e, n=n).public_key()
        return pubkey.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    if normalised.startswith("ECDSA-"):
        curve_name = normalised.split("-", 1)[1]
        curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}
        if curve_name not in curves:
            raise ValueError(f"Cannot read PEM for ECDSA curve {curve_name!r}")
        # CKA_EC_POINT is the DER-encoded OCTET STRING wrapping the raw point.
        ec_point_der = bytes(session.getAttributeValue(pub_handle, [PyKCS11.CKA_EC_POINT])[0])
        # The first two bytes are the OCTET STRING tag/length; strip them.
        # OCTET STRING values longer than 127 bytes use long-form length encoding.
        if not ec_point_der or ec_point_der[0] != 0x04:
            raise ValueError("CKA_EC_POINT did not begin with an OCTET STRING tag")
        if ec_point_der[1] & 0x80:
            n_len_bytes = ec_point_der[1] & 0x7f
            point = ec_point_der[2 + n_len_bytes:]
        else:
            point = ec_point_der[2:]
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curves[curve_name], point)
        return pubkey.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    raise ValueError(f"Cannot read PEM for unsupported key type {normalised!r}")
