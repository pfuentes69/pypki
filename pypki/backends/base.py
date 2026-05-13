"""
Backend contract — :class:`CryptoBackend` and :class:`KeyHandle`.

This is the internal interface :class:`KeyManagementService` dispatches
through. Software and PKCS#11 are the only two implementations
(see :doc:`../../doc/kms-specs.md` §3 — backend topology). Future
backends (cloud KMS, etc.) plug in here.

Scope at this phase: the minimum surface needed to load a key from a
``KeyStorage`` row and sign a pre-computed digest with it. The full
surface from kms-specs.md §5 (``generate_key``, ``import_key``,
``find_key``, ``list_keys``, ``delete_key``, ``get_public_key_der``)
will be added in Phase 5 when the provider-aware management API lands.
"""
from typing import Protocol, runtime_checkable


class BackendError(RuntimeError):
    """Backend-level error not specific to a particular vendor.

    Carries optional ``key_id`` / ``provider_id`` metadata so the Flask
    error handler (CR-0005) can render a structured 503 body naming
    the failing component without re-deriving it. The fields default
    to ``None``; the backend / KMS layer attaches them on the throw
    site when the context is available."""

    def __init__(self, message: str = "", *, key_id: int | None = None,
                 provider_id: int | None = None):
        super().__init__(message)
        self.key_id = key_id
        self.provider_id = provider_id


class BackendNotActive(BackendError):
    """Raised when an operation is attempted on a backend that has not
    been opened yet (or has been closed)."""


class KeyMissingOnToken(BackendError):
    """Raised by a PKCS#11 backend when an operation references a
    ``KeyStorage`` row whose on-token ``CKO_PRIVATE_KEY`` object can no
    longer be located by ``CKA_ID``.

    Distinct from :class:`BackendNotActive` (which means the backend
    itself is not open). A ``KeyMissingOnToken`` means the backend is
    healthy but the on-token material has gone missing — typically
    because an operator deleted it out-of-band (``pkcs11-tool
    --delete-object`` etc.) and the ``KeyStorage`` row is now drifted.
    Caught and re-surfaced cleanly by the management UI and routes."""


# ── Subclasses of BackendNotActive that distinguish *why* a PKCS#11
# backend could not be opened. All three are ``BackendNotActive`` so
# existing ``except BackendNotActive:`` patterns keep working
# unchanged; new call sites that want to render specific guidance to
# the operator can catch the subclass instead.

class SlotNotFound(BackendNotActive):
    """The PKCS#11 module loaded but the configured slot / token label
    is not present. Typical causes: the token was deleted out-of-band
    (``softhsm2-util --delete-token``, removed hardware partition),
    the slot was never initialised, or the operator misconfigured
    ``slot_label``. Surfaces as ``token_check.reason="slot-missing"``
    on the management API."""


class AuthenticationFailed(BackendNotActive):
    """The module loaded and the slot was found, but ``C_Login``
    rejected the credentials — wrong PIN, token reinitialised with a
    new PIN, PIN locked after too many failed attempts, or role
    mismatch. Surfaces as ``token_check.reason="auth-failed"``."""


class ModuleLoadFailed(BackendNotActive):
    """The PKCS#11 shared library could not be loaded (path wrong,
    ABI mismatch, missing dependency). Distinct from the above
    because the diagnosis points the operator at deployment config
    rather than token state. Surfaces as
    ``token_check.reason="module-error"``."""


class KeyHandle:
    """
    Opaque handle to a loaded key.

    Carries the ``KeyStorage.id`` and the ``provider_id`` so the KMS can
    route subsequent operations to the right backend without going back
    to the database.

    The ``_state`` attribute is backend-private — for software, it holds
    the cached :class:`KeyTools` (PEM-loaded); for PKCS#11, it holds the
    :class:`KeyTools` whose internal session points at the on-token
    object. Callers above the KMS must not touch it.
    """

    __slots__ = ("key_id", "provider_id", "_state")

    def __init__(self, key_id: int, provider_id: int, state):
        self.key_id = int(key_id)
        self.provider_id = int(provider_id)
        self._state = state

    def __repr__(self) -> str:
        return f"<KeyHandle key_id={self.key_id} provider_id={self.provider_id}>"


@runtime_checkable
class CryptoBackend(Protocol):
    """
    Protocol every backend implements. Stateful — a backend instance is
    bound to one provider for its lifetime and tracks activation state
    internally.
    """

    def open(self, provider: dict, secret_override: bytes = None) -> None:
        """
        Activate the backend against the given provider record. For
        software, this resolves the PIN and derives the KEK. For PKCS#11,
        this opens a session and logs in. Raise on failure.
        Calling ``open()`` on an already-active backend is a no-op.

        ``secret_override`` bypasses the provider's ``auth_secret_ref``
        resolver and uses the supplied bytes as the PIN directly. Used by
        the activation API for ``operator:prompt`` providers, where the
        PIN is supplied at runtime and never stored.
        """
        ...

    def close(self) -> None:
        """
        Deactivate the backend. For software, drop the KEK from memory.
        For PKCS#11, close the session. Idempotent.
        """
        ...

    def is_active(self) -> bool:
        """Return whether the backend is currently activated."""
        ...

    def load_key(self, record: dict) -> KeyHandle:
        """
        Materialise the ``KeyStorage`` row identified by ``record`` into
        a :class:`KeyHandle` ready for signing. Raise
        :class:`BackendNotActive` if the backend is not open.
        """
        ...

    def unload_key(self, handle: KeyHandle) -> None:
        """
        Release any per-key resources associated with the handle. Idempotent.
        Closing the provider-level session is the responsibility of
        :meth:`close`, not this method.
        """
        ...

    def sign_digest(
        self,
        handle: KeyHandle,
        tbs_digest: bytes,
        signing_algorithm: str = None,
    ) -> bytes:
        """Sign a pre-computed digest. Returns the raw signature bytes.

        ``signing_algorithm`` is the CR-0003 token (`rsa-sha256`,
        `ecdsa-sha256`, …). The digest's hash function must match the
        token. When omitted, backends fall back to legacy SHA-256
        behaviour.
        """
        ...

    def list_keys(self) -> list[dict]:
        """Enumerate the backend's native key store and return one dict per
        key. Used by the token-aware key listing (kms-specs.md §18.1).

        - :class:`SoftwareBackend` returns ``[]`` — software keys live
          exclusively in ``KeyStorage``, there is nothing parallel to
          enumerate.
        - :class:`PKCS11Backend` returns one entry per on-token
          ``CKO_PRIVATE_KEY`` object, carrying its hex CKA_ID, label,
          normalised key type, paired public key PEM, and an
          ``unimportable_reason`` discriminator for rows the API must
          surface but cannot import.

        Raises :class:`BackendNotActive` when the backend is not open.
        """
        ...
