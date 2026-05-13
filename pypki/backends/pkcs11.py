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
from .base import (
    AuthenticationFailed,
    BackendNotActive,
    KeyHandle,
    KeyMissingOnToken,
    ModuleLoadFailed,
    SlotNotFound,
)


# PKCS#11 CKR_* return codes that map to login-time authentication
# failures (CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_USER_PIN_NOT_INITIALIZED,
# CKR_USER_TYPE_INVALID). The integer values are stable across PKCS#11
# versions; held here so the classification in :meth:`PKCS11Backend.open`
# is grep-able.
_AUTH_FAILED_CKRS = frozenset({
    int(PyKCS11.CKR_PIN_INCORRECT),
    int(PyKCS11.CKR_PIN_LOCKED),
    int(PyKCS11.CKR_PIN_EXPIRED),
    int(PyKCS11.CKR_USER_PIN_NOT_INITIALIZED),
    int(PyKCS11.CKR_USER_TYPE_INVALID),
})

# CKR_* codes that mean the slot or token is gone (vs a generic
# session-handle error that the existing reconnect path covers).
_SLOT_MISSING_CKRS = frozenset({
    int(PyKCS11.CKR_SLOT_ID_INVALID),
    int(PyKCS11.CKR_TOKEN_NOT_PRESENT),
    int(PyKCS11.CKR_TOKEN_NOT_RECOGNIZED),
})

# CKR_* codes that mid-session ``sign_digest`` should treat as
# "session probably stale, try one reconnect" (CR-0004). The set is
# wider than the original Phase 3 pair (`CKR_SESSION_HANDLE_INVALID`
# + `CKR_DEVICE_REMOVED`) because real-world out-of-band mutations
# of the token (`softhsm2-util --delete-token`, USB unplug, token
# reinitialisation) surface as a different code depending on the
# vendor / state. If the reconnect itself fails, its own classified
# exception propagates and the KMS evicts the cached backend.
_RECONNECTABLE_CKRS = frozenset({
    int(PyKCS11.CKR_SESSION_HANDLE_INVALID),
    int(PyKCS11.CKR_SESSION_CLOSED),
    int(PyKCS11.CKR_DEVICE_REMOVED),
    int(PyKCS11.CKR_DEVICE_ERROR),
    int(PyKCS11.CKR_TOKEN_NOT_PRESENT),
    int(PyKCS11.CKR_TOKEN_NOT_RECOGNIZED),
})


def _open_session_classified(helper, pin: str, slot_label: str, provider: dict) -> None:
    """Open the PKCS#11 session for ``provider`` and classify any
    failure into the matching :class:`BackendNotActive` subclass.

    Shared between :meth:`PKCS11Backend.open` (activation) and
    :meth:`PKCS11Backend._reconnect` (mid-session recovery) so the
    UI sees the same `slot-missing` / `auth-failed` / `module-error`
    reason regardless of *when* the failure shows up.

    Each typed exception carries ``provider_id`` (CR-0005) so the
    Flask error handler can render a structured 503 body without
    re-deriving the context.
    """
    pid = provider.get("id")
    plabel = provider.get("label")
    try:
        helper.open_session(pin, slot_label=slot_label)
    except PyKCS11.PyKCS11Error as e:
        ckr = int(getattr(e, "value", -1))
        if ckr in _AUTH_FAILED_CKRS:
            raise AuthenticationFailed(
                f"PKCS11Backend: authentication failed for provider "
                f"id={pid} ('{plabel}') — PIN was rejected ({e}). "
                f"Common cause: token was reinitialised with a new PIN.",
                provider_id=pid,
            ) from e
        if ckr in _SLOT_MISSING_CKRS:
            raise SlotNotFound(
                f"PKCS11Backend: slot / token unavailable for provider "
                f"id={pid} ('{plabel}') — {e}. The slot may have been "
                f"deleted or the token removed.",
                provider_id=pid,
            ) from e
        raise BackendNotActive(
            f"PKCS11Backend: failed to open session for provider "
            f"id={pid} ('{plabel}'): {e}",
            provider_id=pid,
        ) from e
    except RuntimeError as e:
        msg = str(e)
        if "no token with label" in msg or "No PKCS#11 tokens found" in msg:
            raise SlotNotFound(
                f"PKCS11Backend: slot_label={slot_label!r} not present on "
                f"the module for provider id={pid} ('{plabel}'): {e}",
                provider_id=pid,
            ) from e
        raise BackendNotActive(
            f"PKCS11Backend: failed to open session for provider "
            f"id={pid} ('{plabel}'): {e}",
            provider_id=pid,
        ) from e
    except Exception as e:
        raise BackendNotActive(
            f"PKCS11Backend: failed to open session for provider "
            f"id={pid} ('{plabel}'): {e}",
            provider_id=pid,
        ) from e


def _classify_pkcs11_error_midsession(e, provider: dict):
    """Map a mid-session ``PyKCS11Error`` to a typed
    :class:`BackendNotActive` subclass without re-running activation.
    Used by ``list_keys`` / ``find_key_by_id`` where CR-0004 decision
    2 says "no silent retry" — the caller wants the typed reason
    immediately. ``provider_id`` is attached on the throw site so
    the Flask error handler can name the failing provider."""
    if not isinstance(e, PyKCS11.PyKCS11Error):
        return None
    ckr = int(getattr(e, "value", -1))
    pid = provider.get("id") if provider else None
    plabel = provider.get("label") if provider else None
    if ckr in _AUTH_FAILED_CKRS:
        return AuthenticationFailed(
            f"PKCS11Backend: authentication failed mid-session on "
            f"provider id={pid} ('{plabel}'): {e}",
            provider_id=pid,
        )
    if ckr in _SLOT_MISSING_CKRS:
        return SlotNotFound(
            f"PKCS11Backend: slot / token unavailable mid-session on "
            f"provider id={pid} ('{plabel}'): {e}",
            provider_id=pid,
        )
    return None


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


# RFC 8017 §9.2 — DigestInfo prefix that PKCS#1 v1.5 signatures carry
# before the digest. Keyed by hash name so the CR-0003 dispatch in
# `_sign_with_state` can pick the right one for `rsa-sha256`,
# `rsa-sha384`, and `rsa-sha512`. Each prefix is the DER-encoded
# `DigestInfo` structure ending with the `OCTET STRING` tag + length;
# the actual digest bytes follow immediately.
_RSA_PKCS_DIGESTINFO_BY_HASH = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
# Expected raw-digest length per hash (used to reject malformed inputs
# before the token call).
_RSA_DIGEST_LEN_BY_HASH = {"sha256": 32, "sha384": 48, "sha512": 64}

# Back-compat alias for any out-of-tree caller — same bytes as SHA-256
# entry above. Kept temporarily; new code should use the by-hash table.
_SHA256_RSA_PKCS_DIGESTINFO = _RSA_PKCS_DIGESTINFO_BY_HASH["sha256"]


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
            except Exception as e:
                # Module load failures originate from ``PyKCS11Lib.load``
                # (missing .so, bad ABI, etc.) — diagnose separately from
                # token-state failures so the operator looks at the
                # deployment config, not the token.
                raise ModuleLoadFailed(
                    f"PKCS11Backend: failed to load PKCS#11 module "
                    f"{module_path!r} for provider id={provider.get('id')} "
                    f"('{provider.get('label')}'): {e}",
                    provider_id=provider.get("id"),
                ) from e

            # Session-open + classification shared with the mid-session
            # reconnect path (CR-0004) so activation-time and mid-session
            # failures surface as the same typed exception.
            _open_session_classified(helper, pin, slot_label, provider)

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
            try:
                token_object = self._find_private_by_id(cka_id_bytes)
            except KeyMissingOnToken as e:
                # Enrich with the KeyStorage id at the layer that knows
                # it (CR-0005) so the Flask error handler can render the
                # recovery URL pointing at /key_details.html?id=…
                e.key_id = record.get("id")
                raise
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
        bytes. Raises :class:`KeyMissingOnToken` if not found — distinct
        from session / login failures so callers can render a clean
        "key has been deleted from the HSM" message rather than a bare
        500. Caller must hold ``self._lock``."""
        session = self._helper.get_session()
        priv_keys = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_ID, cka_id_bytes),
        ])
        if not priv_keys:
            raise KeyMissingOnToken(
                f"PKCS11Backend: private key with CKA_ID={cka_id_bytes.hex()} "
                f"not found on provider id={self._provider.get('id')}",
                provider_id=self._provider.get("id"),
            )
        return priv_keys[0]

    def list_keys(self) -> list[dict]:
        """
        Enumerate every ``CKO_PRIVATE_KEY`` object on the open session and
        return one dict per key with the metadata needed to render a row in
        the "token-aware" key listing (kms-specs.md §18.1).

        Each entry has::

            {
                "hsm_token_id":       <hex CKA_ID>,
                "cka_label":          <CKA_LABEL or None>,
                "key_type":           <"RSA-3072" | "ECDSA-P-256" | … | None>,
                "public_key":         <PEM SubjectPublicKeyInfo or None>,
                "unimportable_reason": None
                                      | "unsupported_key_type"
                                      | "public_key_unavailable",
            }

        Per CR-0001 decision 4, the public-key DER is read **only** from the
        paired ``CKO_PUBLIC_KEY`` object (matched by ``CKA_ID``); if it is
        missing or unreadable, the row surfaces with
        ``unimportable_reason="public_key_unavailable"`` and ``public_key=None``.
        Per decision 3, keys whose ``CKA_KEY_TYPE`` does not map to the §8.1
        conservative subset surface with
        ``unimportable_reason="unsupported_key_type"`` and ``key_type=None``.
        Such rows are visible so the operator knows the slot has objects on
        it, but pyPKI offers no action on them.
        """
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.list_keys: backend is not open")
            session = self._helper.get_session()

            # CR-0004 decision 2: diagnostic operations do not retry.
            # If the session has gone stale between activation and this
            # call (token deleted, slot reinitialised), surface the
            # typed exception immediately so the adapter can map it to
            # the right ``token_enumeration.reason``.
            try:
                priv_objs = session.findObjects([
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                ])
            except PyKCS11.PyKCS11Error as e:
                typed = _classify_pkcs11_error_midsession(e, self._provider)
                if typed is not None:
                    raise typed from e
                raise

            results: list[dict] = []
            for priv in priv_objs:
                cka_id_raw = session.getAttributeValue(priv, [PyKCS11.CKA_ID])[0]
                if not cka_id_raw:
                    # PKCS#11 allows objects without CKA_ID; pyPKI cannot
                    # address such a key, so it is invisible to the API.
                    continue
                cka_id_bytes = bytes(cka_id_raw)
                hex_id = cka_id_bytes.hex()
                label = _read_cka_label(session, priv)

                # Algorithm normalisation. _normalise_key_type_from_token
                # returns "ECDSA-unknown" for curves outside the §8.1 table,
                # and raises ValueError for entirely foreign key types.
                cka_key_type = session.getAttributeValue(
                    priv, [PyKCS11.CKA_KEY_TYPE]
                )[0]
                try:
                    normalised = _normalise_key_type_from_token(
                        session, priv, cka_key_type,
                    )
                except (ValueError, PyKCS11.PyKCS11Error):
                    results.append({
                        "hsm_token_id": hex_id,
                        "cka_label": label,
                        "key_type": None,
                        "public_key": None,
                        "unimportable_reason": "unsupported_key_type",
                    })
                    continue
                if normalised.endswith("-unknown"):
                    results.append({
                        "hsm_token_id": hex_id,
                        "cka_label": label,
                        "key_type": None,
                        "public_key": None,
                        "unimportable_reason": "unsupported_key_type",
                    })
                    continue

                # Paired public-key object (preferred). CR-0003 adds a
                # fallback to reading the public attributes off the
                # private-key handle itself when the paired object is
                # missing — covers the common "operator deleted only
                # the pubkey out-of-band" case without surfacing the
                # row as read-only.
                pub_objs = session.findObjects([
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_ID, cka_id_bytes),
                ])
                pem_handle = pub_objs[0] if pub_objs else priv
                try:
                    public_pem = _read_public_key_pem_attributes(
                        session, pem_handle, normalised,
                    )
                except Exception as e:
                    # Broad catch: vendors return different attributes as
                    # ``None`` when a public-key object is partially missing,
                    # which surfaces here as ``TypeError`` (None → bytes),
                    # ``ValueError`` (curve mismatch), ``PyKCS11Error``, or
                    # something else entirely. Any failure means the key is
                    # importable as "public key unavailable" rather than
                    # blocking the whole list — preserves CR-0001 decision 4.
                    logger.warning(
                        f"PKCS11Backend.list_keys: CKA_ID={hex_id} on provider "
                        f"id={self._provider.get('id')} — paired public key "
                        f"unreadable: {e!r}"
                    )
                    results.append({
                        "hsm_token_id": hex_id,
                        "cka_label": label,
                        "key_type": normalised,
                        "public_key": None,
                        "unimportable_reason": "public_key_unavailable",
                    })
                    continue

                results.append({
                    "hsm_token_id": hex_id,
                    "cka_label": label,
                    "key_type": normalised,
                    "public_key": public_pem,
                    "unimportable_reason": None,
                })
            return results

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
            except KeyMissingOnToken:
                # Genuine "no such CKA_ID on the token" — the public
                # contract of find_key_by_id is to return None, not to
                # raise. Distinct from the session-level failure cases
                # caught further down with the mid-session classifier.
                return None
            try:
                cka_key_type = session.getAttributeValue(priv_handle, [PyKCS11.CKA_KEY_TYPE])[0]
            except PyKCS11.PyKCS11Error as e:
                # CR-0004 decision 2: diagnostic operations do not retry.
                # Classify the mid-session failure so probe_key_on_token
                # / explicit-import callers see the typed reason.
                typed = _classify_pkcs11_error_midsession(e, self._provider)
                if typed is not None:
                    raise typed from e
                raise
            normalised = _normalise_key_type_from_token(session, priv_handle, cka_key_type)
            cka_label = _read_cka_label(session, priv_handle)
            # Prefer the paired CKO_PUBLIC_KEY for the SPKI. CR-0003
            # falls back to attributes on the private-key handle when
            # the paired object is missing — covers the "operator
            # deleted the pubkey out-of-band" case while still raising
            # a clean error when even the private-key attributes don't
            # yield a usable public key.
            pub_objs = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_ID, cka_id_bytes),
            ])
            if pub_objs:
                public_pem = _read_public_key_pem_attributes(session, pub_objs[0], normalised)
                # Fall back to the public key's label if the private one is empty.
                if not cka_label:
                    cka_label = _read_cka_label(session, pub_objs[0])
            else:
                try:
                    public_pem = _read_public_key_pem_attributes(
                        session, priv_handle, normalised,
                    )
                    logger.info(
                        f"PKCS11Backend.find_key_by_id: CKA_ID={hsm_token_id} on "
                        f"provider id={self._provider.get('id')} — paired public "
                        f"key missing; reconstructed from private-key attributes"
                    )
                except Exception as e:
                    raise RuntimeError(
                        f"PKCS11Backend.find_key_by_id: private key {hsm_token_id} "
                        f"found but the paired public key is missing and the "
                        f"private-key attribute fallback failed: {e}"
                    ) from e
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

    def sign_digest(
        self,
        handle: KeyHandle,
        tbs_digest: bytes,
        signing_algorithm: str = None,
    ) -> bytes:
        """Sign a TBS digest. ``signing_algorithm`` is the CR-0003 token.

        Today only `rsa-sha256` and `ecdsa-sha256` are wired in this
        backend; any other token raises ``UnsupportedSigningAlgorithm``
        before the session is touched. When ``signing_algorithm`` is
        None the legacy SHA-256 behaviour is preserved (utility
        callers that don't carry algorithm context).
        """
        with self._lock:
            if self._helper is None:
                raise BackendNotActive("PKCS11Backend.sign_digest: backend is not open")
            try:
                return self._sign_with_state(
                    handle._state, tbs_digest, signing_algorithm=signing_algorithm
                )
            except PyKCS11.PyKCS11Error as e:
                # Mid-session classification (CR-0004). The reconnect
                # path covers any CKR code where retrying the session
                # might recover; everything else is classified and
                # propagated as a typed exception so the KMS / Flask
                # error handler can render the right operator
                # guidance.
                if int(e.value) not in _RECONNECTABLE_CKRS:
                    typed = _classify_pkcs11_error_midsession(e, self._provider)
                    if typed is not None:
                        raise typed from e
                    raise
                logger.warning(
                    f"PKCS11Backend: session invalidated ({e}); attempting one reconnect "
                    f"for provider id={self._provider.get('id')}"
                )
                # CR-0004 decision 1: one reconnect attempt, no more.
                # ``_reconnect`` raises a typed BackendNotActive
                # subclass on failure (`SlotNotFound` /
                # `AuthenticationFailed` / `ModuleLoadFailed`); the
                # KMS catches those and evicts the cached backend.
                self._reconnect()
                # The new session has a different CK_OBJECT_HANDLE for the same
                # on-token object; re-find it by CKA_ID. If the on-token
                # object itself is gone (vs just the session), the find
                # raises ``KeyMissingOnToken`` which propagates cleanly.
                cka_id_bytes = _validate_cka_id_hex(handle._state.cka_id)
                handle._state.token_object = self._find_private_by_id(cka_id_bytes)
                return self._sign_with_state(
                    handle._state, tbs_digest, signing_algorithm=signing_algorithm
                )

    # ── internal helpers ─────────────────────────────────────────────────────

    def _sign_with_state(
        self,
        state: _Pkcs11KeyState,
        tbs_digest: bytes,
        signing_algorithm: str = None,
    ) -> bytes:
        """Run the actual sign call. Caller must hold ``self._lock``."""
        from .. import signing_algorithm as _sa

        # Default to SHA-256 if no token was supplied (legacy callers).
        token = signing_algorithm
        if token is None:
            if state.cka_key_type == PyKCS11.CKK_RSA:
                token = _sa.RSA_SHA256
            elif state.cka_key_type == PyKCS11.CKK_EC:
                token = _sa.ECDSA_SHA256

        # Validate token is wired in this backend. PSS / EdDSA stay
        # reserved until their dedicated mechanisms (and dummy-sign
        # builder shape, for PSS) land.
        _RSA_TOKENS = (_sa.RSA_SHA256, _sa.RSA_SHA384, _sa.RSA_SHA512)
        _ECDSA_TOKENS = (_sa.ECDSA_SHA256, _sa.ECDSA_SHA384, _sa.ECDSA_SHA512)
        if token not in _RSA_TOKENS + _ECDSA_TOKENS:
            raise _sa.UnsupportedSigningAlgorithm(
                f"PKCS11Backend: signing_algorithm {token!r} is not wired in "
                "this backend yet"
            )

        session = self._helper.get_session()
        hash_name = _sa.hash_family_of(token)  # "sha256" | "sha384" | "sha512"

        if state.cka_key_type == PyKCS11.CKK_RSA:
            if token not in _RSA_TOKENS:
                raise _sa.SigningAlgorithmKeyMismatch(
                    f"PKCS11Backend: signing_algorithm {token!r} not compatible "
                    "with RSA HSM key"
                )
            # RSA PKCS#1 v1.5 — prepend the matching DigestInfo so
            # CKM_RSA_PKCS (which does padding only, not hashing — see
            # kms-specs.md §5) produces a verifiable signature.
            expected_len = _RSA_DIGEST_LEN_BY_HASH[hash_name]
            if len(tbs_digest) != expected_len:
                raise ValueError(
                    f"PKCS11Backend: RSA sign for {token!r} expects a "
                    f"{expected_len}-byte {hash_name.upper()} digest, "
                    f"got {len(tbs_digest)} bytes"
                )
            payload = _RSA_PKCS_DIGESTINFO_BY_HASH[hash_name] + tbs_digest
            mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            return bytes(session.sign(state.token_object, payload, mech))

        if state.cka_key_type == PyKCS11.CKK_EC:
            if token not in _ECDSA_TOKENS:
                raise _sa.SigningAlgorithmKeyMismatch(
                    f"PKCS11Backend: signing_algorithm {token!r} not compatible "
                    "with ECDSA HSM key"
                )
            # ECDSA — CKM_ECDSA is hash-agnostic; the token signs whatever
            # digest length we hand it. Output is raw r||s; encode as DER
            # SEQUENCE to match the software backend.
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
        :class:`BackendNotActive` (or one of its typed subclasses —
        :class:`SlotNotFound`, :class:`AuthenticationFailed` — via the
        shared ``_open_session_classified`` helper) when the slot /
        PIN no longer authorise the activation."""
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
        # Shared classification path with PKCS11Backend.open — a
        # reconnect that fails because the slot was deleted or the
        # PIN was rotated raises ``SlotNotFound`` /
        # ``AuthenticationFailed`` (CR-0004) rather than a raw
        # PyKCS11Error.
        _open_session_classified(self._helper, pin, slot_label, self._provider)
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


def _read_public_key_pem_attributes(session, handle, normalised: str) -> str:
    """Reconstruct the PEM ``SubjectPublicKeyInfo`` from a token
    object's attributes. Works on *either* a public-key handle (the
    original call site) or a private-key handle (the CR-0003 fallback
    path used when the paired ``CKO_PUBLIC_KEY`` object is missing).

    Strategy, attempted in order:

    1. ``CKA_PUBLIC_KEY_INFO`` — PKCS#11 v3.x DER-encoded SPKI;
       optional on private-key objects but the most direct path when
       the vendor supports it.
    2. Per-algorithm reconstruction:
       - RSA: ``CKA_MODULUS`` + ``CKA_PUBLIC_EXPONENT`` (both listed
         in the PKCS#11 RSA private-key template, well-supported).
       - EC: ``CKA_EC_POINT`` (standard on public handles; SoftHSM2
         and several vendors also expose it on private handles).

    Raises :class:`ValueError` if neither path yields a usable PEM —
    callers (``list_keys`` / ``find_key_by_id``) decide how to surface
    that (muted ``public_key_unavailable`` badge in the list view; a
    clear error in the explicit-import path).
    """
    # Path 1 — PKCS#11 v3 CKA_PUBLIC_KEY_INFO.
    cka_public_key_info = getattr(PyKCS11, "CKA_PUBLIC_KEY_INFO", None)
    if cka_public_key_info is not None:
        try:
            spki_attr = session.getAttributeValue(handle, [cka_public_key_info])[0]
        except PyKCS11.PyKCS11Error:
            spki_attr = None
        if spki_attr:
            try:
                return serialization.load_der_public_key(bytes(spki_attr)).public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
            except Exception:
                # CKA_PUBLIC_KEY_INFO returned bytes but they did not
                # parse as a SubjectPublicKeyInfo (vendor-specific
                # encoding). Fall through to the algorithm-specific
                # path below.
                pass

    # Path 2 — algorithm-specific reconstruction.
    if normalised.startswith("RSA-"):
        modulus, exponent = session.getAttributeValue(
            handle, [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT]
        )
        if modulus is None or exponent is None:
            raise ValueError(
                "RSA public components (CKA_MODULUS / CKA_PUBLIC_EXPONENT) "
                "not readable on this handle"
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
        ec_point_attr = session.getAttributeValue(handle, [PyKCS11.CKA_EC_POINT])[0]
        if ec_point_attr is None:
            raise ValueError(
                "CKA_EC_POINT not readable on this handle "
                "(typical for vendor-restricted private-key objects)"
            )
        # CKA_EC_POINT is the DER-encoded OCTET STRING wrapping the raw point.
        # The first two bytes are the OCTET STRING tag/length; strip them.
        # OCTET STRING values longer than 127 bytes use long-form length encoding.
        ec_point_der = bytes(ec_point_attr)
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


# Compatibility alias for the original name. Several call sites
# (generate_key, find_key_by_id) use this with a public-key handle;
# the new helper accepts either kind, so the alias keeps grep-ability
# intact without a wider rename.
_read_public_key_pem = _read_public_key_pem_attributes
