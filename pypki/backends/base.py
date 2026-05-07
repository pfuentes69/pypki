"""
Backend contract — :class:`CryptoBackend` and :class:`KeyHandle`.

This is the internal interface :class:`KeyManagementService` dispatches
through. Software and PKCS#11 are the only two implementations
(see :doc:`../../doc/kms-strategy.md` §3 — backend topology). Future
backends (cloud KMS, etc.) plug in here.

Scope at this phase: the minimum surface needed to load a key from a
``KeyStorage`` row and sign a pre-computed digest with it. The full
surface from kms-strategy.md §5 (``generate_key``, ``import_key``,
``find_key``, ``list_keys``, ``delete_key``, ``get_public_key_der``)
will be added in Phase 5 when the provider-aware management API lands.
"""
from typing import Protocol, runtime_checkable


class BackendError(RuntimeError):
    """Backend-level error not specific to a particular vendor."""


class BackendNotActive(BackendError):
    """Raised when an operation is attempted on a backend that has not
    been opened yet (or has been closed)."""


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

    def sign_digest(self, handle: KeyHandle, tbs_digest: bytes) -> bytes:
        """Sign a pre-computed digest. Returns the raw signature bytes."""
        ...
