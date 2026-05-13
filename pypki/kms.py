import os
import base64
import contextlib
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .backends import (
    CryptoBackend, KeyHandle, BackendNotActive,
    SoftwareBackend, PKCS11Backend,
)
from .db import PKIDataBase
from .key_encryption import (
    decrypt_pem, encrypt_pem, get_provider_kek, KEKUnavailable
)
from .log import logger


# Valid symmetric key sizes in bits
_AES_SIZES = {128, 192, 256, 512}

# Valid RSA key sizes in bits
_RSA_SIZES = {2048, 3072, 4096, 8192}

# Valid ECDSA curves
_EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


class KeyManagementService:
    """
    Central service for key generation, storage, and signing operations.

    Keys are identified by their KeyStorage.id and cached in memory
    after the first load. The backend (software or HSM) is transparent to
    the caller — sign_digest() works the same regardless of storage type.
    """

    def __init__(self, db: PKIDataBase):
        self.__db = db
        # key_id → KeyHandle. PKCS11Backend / SoftwareBackend produce these.
        self.__handle_cache: dict[int, KeyHandle] = {}
        # provider_id → activated backend (one per provider, per kms-specs.md §5/§6)
        self.__backends: dict[int, CryptoBackend] = {}
        # Guards backend creation/activation against concurrent first-use.
        # Full per-key locking (Gap 7) lands in Phase 3.
        self.__lock = threading.RLock()

    # ── Backend lookup ───────────────────────────────────────────────────────

    @contextlib.contextmanager
    def _evict_on_hard_failure(self, provider_id: int):
        """Context manager: evict the cached backend for ``provider_id``
        when the wrapped block raises :class:`SlotNotFound`,
        :class:`AuthenticationFailed`, or :class:`ModuleLoadFailed`.
        Activation-time failures and mid-session classifications use
        the same set, so this wrapper covers both. CR-0004 decision 3.
        """
        from .backends.base import (
            SlotNotFound, AuthenticationFailed, ModuleLoadFailed,
        )
        try:
            yield
        except (SlotNotFound, AuthenticationFailed, ModuleLoadFailed) as e:
            self._evict_provider(provider_id, reason=type(e).__name__)
            raise

    def _evict_provider(self, provider_id: int, reason: str = "hard-failure") -> None:
        """Remove the cached backend for ``provider_id`` and clear any
        handles it owned. Used after a hard activation / mid-session
        failure (``SlotNotFound`` / ``AuthenticationFailed`` /
        ``ModuleLoadFailed``) per CR-0004 decision 3 — otherwise the
        cached broken backend keeps replaying the same exception even
        after the operator fixes the slot."""
        with self.__lock:
            backend = self.__backends.pop(provider_id, None)
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    logger.exception(
                        f"KMS._evict_provider: backend.close() failed for "
                        f"provider id={provider_id}"
                    )
            for kid in list(self.__handle_cache.keys()):
                if self.__handle_cache[kid].provider_id == provider_id:
                    del self.__handle_cache[kid]
        logger.info(
            f"KMS._evict_provider: evicted provider id={provider_id} "
            f"(reason={reason})"
        )

    def _get_backend(self, provider_id: int) -> CryptoBackend:
        """Return an activated backend for the provider, creating it if needed.

        Backend instantiation + activation is serialised by ``self.__lock`` so
        concurrent first-use of the same provider does not produce two
        backend instances (or two PKCS#11 sessions).
        """
        with self.__lock:
            backend = self.__backends.get(provider_id)
            if backend is not None:
                return backend
            with self.__db.connection():
                provider = self.__db.get_provider_by_id(provider_id)
            if not provider:
                raise KeyError(f"KMS: provider_id={provider_id} not found")
            kind = provider.get("kind")
            if kind == "software":
                backend = SoftwareBackend()
            elif kind == "pkcs11":
                backend = PKCS11Backend()
            else:
                raise ValueError(
                    f"KMS: provider id={provider_id} has unknown kind={kind!r}"
                )
            backend.open(provider)  # may raise BackendNotActive on PIN/KEK failure
            self.__backends[provider_id] = backend
            return backend

    def activate_provider(self, provider_id: int, pin: str = None) -> None:
        """
        Force activation of a provider's backend now (rather than lazily on
        first use). Used by the management API
        (``POST /api/crypto-providers/{id}/activate``) — see
        doc/kms-specs.md §6.

        ``pin`` is the operator-supplied PIN for ``operator:prompt``
        providers; ignored otherwise. Raises :class:`KeyError` for unknown
        provider id, :class:`ValueError` for protocol mismatches (e.g. PIN
        supplied but provider isn't operator-prompt, or vice versa), and
        :class:`BackendError`/its subclasses on activation failure.
        """
        from .backends.base import BackendNotActive
        with self.__db.connection():
            provider = self.__db.get_provider_by_id(provider_id)
        if not provider:
            raise KeyError(f"KMS: provider_id={provider_id} not found")

        ref = (provider.get("auth_secret_ref") or "").strip()
        is_operator = ref == "operator:prompt"

        if is_operator and not pin:
            raise ValueError(
                f"KMS: provider id={provider_id} ('{provider.get('label')}') "
                f"is operator:prompt; activation requires a PIN"
            )
        if pin and not is_operator:
            raise ValueError(
                f"KMS: provider id={provider_id} ('{provider.get('label')}') "
                f"resolves its PIN automatically (auth_secret_ref={ref!r}); "
                f"do not supply one in the activate request"
            )

        with self.__lock:
            backend = self.__backends.get(provider_id)
            if backend is not None and backend.is_active():
                logger.info(
                    f"KMS.activate_provider: id={provider_id} already active; no-op"
                )
                return
            if backend is None:
                kind = provider.get("kind")
                if kind == "software":
                    backend = SoftwareBackend()
                elif kind == "pkcs11":
                    backend = PKCS11Backend()
                else:
                    raise ValueError(f"KMS: provider id={provider_id} has unknown kind={kind!r}")
            secret_override = pin.encode("utf-8") if pin else None
            backend.open(provider, secret_override=secret_override)
            self.__backends[provider_id] = backend

    def get_provider_status(self, provider_id: int) -> dict:
        """
        Return a snapshot of a provider's current state. Used by
        ``GET /api/crypto-providers/{id}/status``.
        """
        with self.__db.connection():
            provider = self.__db.get_provider_by_id(provider_id)
        if not provider:
            raise KeyError(f"KMS: provider_id={provider_id} not found")
        with self.__lock:
            backend = self.__backends.get(provider_id)
            active = bool(backend is not None and backend.is_active())
        return {
            "id": provider_id,
            "label": provider.get("label"),
            "kind": provider.get("kind"),
            "auto_activate": bool(provider.get("auto_activate")),
            "auth_secret_ref": provider.get("auth_secret_ref"),
            "state": "active" if active else "inactive",
        }

    def activate_auto_providers(self) -> dict:
        """
        Activate every provider with ``auto_activate=TRUE`` at startup.
        Failures are logged loudly but do not raise — CAs bound to a
        failing provider will report "provider unavailable" cleanly on
        first sign attempt (kms-specs.md §6).

        Returns a summary dict with ``activated``, ``skipped``, and
        ``errors`` counts for the caller to log.
        """
        with self.__db.connection():
            providers = self.__db.list_providers()
        activated = skipped = errors = 0
        for provider in providers:
            if not provider.get("auto_activate"):
                skipped += 1
                continue
            pid = provider["id"]
            try:
                self.activate_provider(pid)
                activated += 1
            except Exception as e:
                errors += 1
                logger.error(
                    f"KMS.activate_auto_providers: provider id={pid} "
                    f"('{provider.get('label')}') failed to activate: {e}"
                )
        logger.info(
            f"KMS.activate_auto_providers: activated={activated} "
            f"skipped={skipped} errors={errors}"
        )
        return {"activated": activated, "skipped": skipped, "errors": errors}

    def deactivate_provider(self, provider_id: int) -> None:
        """
        Close the backend for a provider and evict any of its cached
        handles. Idempotent. Used by the management API
        (Phase 5 — POST /api/crypto-providers/{id}/deactivate).
        """
        with self.__lock:
            backend = self.__backends.pop(provider_id, None)
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    logger.exception(f"KMS: backend.close() failed for provider {provider_id}")
            # Evict cached handles for this provider.
            for kid in list(self.__handle_cache.keys()):
                if self.__handle_cache[kid].provider_id == provider_id:
                    del self.__handle_cache[kid]

    # ── Provider-aware key generation / import / deletion (Phase 5a) ─────────

    def generate_key_in_provider(
        self, provider_id: int, key_type: str, label: str = None
    ) -> dict:
        """
        Generate a fresh key on the given provider's backend and persist a
        ``KeyStorage`` row. Activates the provider on demand. Returns the
        new ``KeyStorage`` id plus the public material so callers (the
        management API, CA-creation flow, …) can use it immediately.

        For software providers, the PEM is encrypted at rest under the
        per-provider KEK. For pkcs11 providers, the keypair is created on
        the token with the mandatory CKA_* attribute set; only the public
        key, key_type, and CKA_ID land in the database.
        """
        backend = self._get_backend(provider_id)
        result = backend.generate_key(key_type=key_type, label=label)

        with self.__db.connection():
            new_id = self.__db.insert_key(
                private_key=result.get("private_key"),
                storage_type=result["storage_type"],
                public_key=result.get("public_key"),
                key_type=result["key_type"],
                hsm_token_id=result.get("hsm_token_id"),
                provider_id=provider_id,
                label=label,
            )
        if new_id is None:
            # Best-effort cleanup if the DB insert failed for an HSM key —
            # otherwise we'd leak the on-token object.
            tok_id = result.get("hsm_token_id")
            if tok_id and isinstance(backend, PKCS11Backend):
                try:
                    backend.delete_key(tok_id)
                except Exception:
                    logger.exception(
                        f"KMS: rollback delete_key({tok_id}) failed after DB error"
                    )
            raise RuntimeError("KMS: failed to persist KeyStorage row for new key")

        logger.info(
            f"KMS: generated {result['key_type']} on provider id={provider_id} "
            f"→ KeyStorage id={new_id}"
        )
        return {
            "key_id": new_id,
            "provider_id": provider_id,
            "key_type": result["key_type"],
            "public_key": result.get("public_key"),
            "label": label,
            "hsm_token_id": result.get("hsm_token_id"),
        }

    def import_pkcs11_key(
        self, provider_id: int, hsm_token_id: str, label: str = None
    ) -> dict:
        """
        Register an *existing* on-token key into ``KeyStorage`` without
        generating new material. Provider must be ``kind='pkcs11'``.
        Returns ``{key_id, provider_id, key_type, public_key, hsm_token_id}``.

        ``hsm_token_id`` is validated as a non-empty hex string with an
        even number of digits (Gap 9) — fails fast with a clear
        :class:`ValueError` rather than crashing inside PyKCS11 on first
        sign.
        """
        # Validate the hex contract at the API boundary, not at sign time.
        from .backends.pkcs11 import _validate_cka_id_hex
        _validate_cka_id_hex(hsm_token_id)
        with self.__db.connection():
            provider = self.__db.get_provider_by_id(provider_id)
        if not provider:
            raise KeyError(f"KMS: provider_id={provider_id} not found")
        if provider.get("kind") != "pkcs11":
            raise ValueError(
                f"KMS: provider id={provider_id} is kind={provider.get('kind')!r}; "
                f"key import is only valid for pkcs11 providers"
            )

        backend = self._get_backend(provider_id)
        if not isinstance(backend, PKCS11Backend):
            raise RuntimeError("KMS: import_pkcs11_key requires a PKCS11Backend")

        found = backend.find_key_by_id(hsm_token_id)
        if not found:
            raise KeyError(
                f"KMS: no on-token private key with CKA_ID={hsm_token_id} on "
                f"provider id={provider_id}"
            )

        # Operator-supplied label wins; otherwise fall back to the on-token
        # CKA_LABEL so the import doesn't lose useful identity information.
        effective_label = label if label else found.get("cka_label")

        with self.__db.connection():
            new_id = self.__db.insert_key(
                private_key=None,
                storage_type="HSM",
                public_key=found["public_key"],
                key_type=found["key_type"],
                hsm_token_id=found["hsm_token_id"],
                provider_id=provider_id,
                label=effective_label,
                # Imported keys: pyPKI does *not* own the on-token objects.
                # delete_key will skip the backend.delete_key call so the
                # operator's pre-existing material survives unregistration.
                key_owned=False,
            )
        if new_id is None:
            raise RuntimeError("KMS: failed to insert imported KeyStorage row")
        logger.info(
            f"KMS: imported on-token key CKA_ID={hsm_token_id} on provider "
            f"id={provider_id} → KeyStorage id={new_id} (label={effective_label!r}, "
            f"key_owned=False)"
        )
        return {
            "key_id": new_id,
            "provider_id": provider_id,
            "key_type": found["key_type"],
            "public_key": found["public_key"],
            "hsm_token_id": found["hsm_token_id"],
            "label": effective_label,
        }

    def probe_key_on_token(self, provider_id: int, hsm_token_id: str) -> dict:
        """
        Cheap on-demand drift check for a single ``KeyStorage`` row whose
        material lives on a PKCS#11 token. Returns::

            {"available": True,  "present": True,  "reason": None}
            {"available": True,  "present": False, "reason": None}
            {"available": False, "present": False, "reason": "<diagnosis>"}

        - ``available=True, present=True`` — the on-token object exists.
        - ``available=True, present=False`` — drift: the row's
          ``hsm_token_id`` is not on the token. Callers (the details
          endpoint, signing pre-flight, etc.) should flip the row's
          ``state`` to ``registered_only``.
        - ``available=False`` — probe could not run; the row's state
          stays unverified. ``reason`` distinguishes the cases the UI
          renders (``"provider-inactive"`` when the backend cannot be
          opened; ``"not_applicable"`` when the provider is software
          or the row carries no ``hsm_token_id``; ``"unknown_provider"``
          when ``provider_id`` does not resolve; ``"backend-error"``
          when the probe itself raised something unexpected).

        Used by ``api_adapters.get_kms_key`` so the key details page
        surfaces drift the moment an operator opens it, not only when
        they walk the keys list. The signing path raises
        :class:`KeyMissingOnToken` directly — see kms-specs.md §18.1
        decision 2 (drift detection scope expanded beyond the list).
        """
        if not hsm_token_id:
            return {"available": False, "present": False, "reason": "not_applicable"}
        with self.__db.connection():
            provider = self.__db.get_provider_by_id(provider_id)
        if not provider:
            return {"available": False, "present": False, "reason": "unknown_provider"}
        if provider.get("kind") != "pkcs11":
            return {"available": False, "present": False, "reason": "not_applicable"}

        from .backends.base import (
            AuthenticationFailed, BackendNotActive,
            ModuleLoadFailed, SlotNotFound,
        )
        try:
            backend = self._get_backend(provider_id)
        except SlotNotFound:
            return {"available": False, "present": False, "reason": "slot-missing"}
        except AuthenticationFailed:
            return {"available": False, "present": False, "reason": "auth-failed"}
        except ModuleLoadFailed:
            return {"available": False, "present": False, "reason": "module-error"}
        except BackendNotActive:
            return {"available": False, "present": False, "reason": "provider-inactive"}
        except Exception:
            logger.exception(
                f"KMS.probe_key_on_token: unexpected error activating provider "
                f"id={provider_id}"
            )
            return {"available": False, "present": False, "reason": "backend-error"}

        if not isinstance(backend, PKCS11Backend):
            return {"available": False, "present": False, "reason": "not_applicable"}

        # Mid-session classification (CR-0004 decision 2). If the
        # cached backend's session has gone bad between activation and
        # now (token deleted, slot reinitialised), ``find_key_by_id``
        # raises a typed BackendNotActive subclass; map it to the
        # same reason set as the activation-time path and evict the
        # broken cached backend so the next call re-runs activation.
        try:
            found = backend.find_key_by_id(hsm_token_id)
        except SlotNotFound:
            self._evict_provider(provider_id, reason="SlotNotFound (mid-session)")
            return {"available": False, "present": False, "reason": "slot-missing"}
        except AuthenticationFailed:
            self._evict_provider(provider_id, reason="AuthenticationFailed (mid-session)")
            return {"available": False, "present": False, "reason": "auth-failed"}
        except ModuleLoadFailed:
            self._evict_provider(provider_id, reason="ModuleLoadFailed (mid-session)")
            return {"available": False, "present": False, "reason": "module-error"}
        except Exception:
            logger.exception(
                f"KMS.probe_key_on_token: find_key_by_id raised for "
                f"provider id={provider_id}, hsm_token_id={hsm_token_id}"
            )
            return {"available": False, "present": False, "reason": "backend-error"}
        return {"available": True, "present": found is not None, "reason": None}

    def list_provider_token_keys(self, provider_id: int) -> list[dict]:
        """
        Enumerate the on-token keys for a ``pkcs11`` provider via
        ``PKCS11Backend.list_keys()``. Activates the provider on demand.

        Used by the token-aware merged listing
        (``api_adapters.list_kms_keys``) per kms-specs.md §18.1. Raises
        :class:`KeyError` for unknown provider, :class:`ValueError` when
        the provider is not ``pkcs11``, and :class:`BackendNotActive` /
        :class:`RuntimeError` on backend activation or enumeration
        failure — callers translate those into the response envelope's
        ``token_enumeration`` flag.
        """
        with self.__db.connection():
            provider = self.__db.get_provider_by_id(provider_id)
        if not provider:
            raise KeyError(f"KMS: provider_id={provider_id} not found")
        if provider.get("kind") != "pkcs11":
            raise ValueError(
                f"KMS: provider id={provider_id} is kind={provider.get('kind')!r}; "
                f"on-token enumeration is only valid for pkcs11 providers"
            )
        # CR-0004 decision 3: evict the cached backend on hard failure so
        # the next call re-runs activation cleanly once the slot / PIN
        # is restored. The backend's ``list_keys`` itself can raise the
        # same typed exceptions mid-session (CR-0004 step 3), so the
        # wrapper covers both activation and enumeration.
        with self._evict_on_hard_failure(provider_id):
            backend = self._get_backend(provider_id)
            return backend.list_keys()

    def export_software_key(self, key_id: int, passphrase: bytes) -> bytes:
        """
        Export an owned software key as a passphrase-encrypted PKCS#8
        PEM (kms-specs.md §18.1 CR-0002).

        Refuses anything other than ``storage_type='Encrypted'`` with
        ``key_owned=TRUE``: HSM-backed keys are non-extractable by §8.2
        policy; imported software keys were brought in by the operator
        and pyPKI is not a re-export channel for material it does not
        own. Both refusals raise :class:`PermissionError` with a
        descriptive message — callers (the management route) map them
        to HTTP 409.

        Returns the PEM bytes. The KEK-protected blob on the row is
        decrypted via the bound :class:`SoftwareBackend`, then the
        plaintext private-key object is re-serialised under
        ``serialization.BestAvailableEncryption(passphrase)`` — the
        Python ``cryptography`` library's PBES2 wrapper (PBKDF2-
        HMAC-SHA256 + AES-256-CBC). The plaintext is never written to
        disk, returned to the caller, or held beyond the function
        scope.
        """
        if not passphrase:
            raise ValueError("KMS.export_software_key: passphrase is required")
        if isinstance(passphrase, str):
            passphrase = passphrase.encode("utf-8")
        if not isinstance(passphrase, (bytes, bytearray)) or len(passphrase) < 12:
            raise ValueError(
                "KMS.export_software_key: passphrase must be at least 12 bytes"
            )

        with self.__db.connection():
            record = self.__db.get_key_record(key_id)
        if not record:
            raise KeyError(f"KMS.export_software_key: key_id={key_id} not found")

        storage_type = record.get("storage_type")
        key_owned = record.get("key_owned")
        if storage_type == "HSM":
            raise PermissionError(
                f"KMS.export_software_key: key_id={key_id} is HSM-backed; "
                f"PKCS#11 private keys are non-extractable by §8.2 policy"
            )
        if storage_type != "Encrypted":
            raise PermissionError(
                f"KMS.export_software_key: key_id={key_id} has "
                f"storage_type={storage_type!r}; only 'Encrypted' software "
                f"keys can be exported"
            )
        if key_owned is False or key_owned == 0:
            raise PermissionError(
                f"KMS.export_software_key: key_id={key_id} was imported "
                f"(key_owned=FALSE); pyPKI does not re-export material it "
                f"does not own"
            )

        # Decrypt under the provider KEK by routing through the bound
        # backend, then re-wrap under the operator passphrase. Going
        # through ``load_key`` keeps the KEK-decryption path consolidated
        # in SoftwareBackend (legacy-PEM detection, error handling) and
        # avoids re-implementing it here.
        provider_id = record.get("provider_id")
        if provider_id is None:
            raise RuntimeError(
                f"KMS.export_software_key: key_id={key_id} has no provider_id"
            )
        backend = self._get_backend(provider_id)
        handle = backend.load_key(record)
        try:
            key_tools = handle._state  # KeyTools instance, see software.py
            pem = key_tools.get_private_key_pem(password=passphrase)
            if not pem:
                raise RuntimeError(
                    f"KMS.export_software_key: key_id={key_id} did not "
                    f"produce a PEM (empty private-key tools state)"
                )
            return pem
        finally:
            backend.unload_key(handle)

    def delete_key(self, key_id: int) -> dict:
        """
        Delete a key. Refuses if any CA / OCSP responder / certificate
        references it (returns ``{"deleted": False, "reason": "in_use",
        "usage": {...}}``). For HSM rows, removes both on-token objects
        before dropping the ``KeyStorage`` row.

        Returns the ``delete_key`` result from PKIDataBase, or None if the
        row does not exist.
        """
        with self.__db.connection():
            record = self.__db.get_key_record(key_id)
        if not record:
            return None

        # Pre-flight usage check so we don't touch the token if the row
        # cannot be deleted anyway.
        with self.__db.connection():
            usage = self.__db.count_key_usage(key_id)
        if usage.get("total", 0) > 0:
            return {"deleted": False, "reason": "in_use", "usage": usage}

        # On-token cleanup for HSM rows — only when pyPKI owns the key.
        # Imported keys (key_owned=FALSE) had the on-token objects created
        # out-of-band by the operator; we leave them in place and only
        # remove the pyPKI registration.
        if record.get("storage_type") == "HSM" and bool(record.get("key_owned", True)):
            tok_id = record.get("hsm_token_id")
            provider_id = record.get("provider_id")
            if tok_id and provider_id is not None:
                try:
                    backend = self._get_backend(provider_id)
                    if isinstance(backend, PKCS11Backend):
                        backend.delete_key(tok_id)
                except Exception:
                    logger.exception(
                        f"KMS.delete_key: on-token delete failed for key_id={key_id}; "
                        f"continuing with DB row removal"
                    )
        elif record.get("storage_type") == "HSM":
            logger.info(
                f"KMS.delete_key: key_id={key_id} is imported (key_owned=False); "
                f"leaving on-token objects intact"
            )

        # Drop in-memory cache and the DB row.
        self.unload_key(key_id)
        with self.__db.connection():
            return self.__db.delete_key(key_id)

    def shutdown(self) -> None:
        """
        Close every active backend and evict every cached handle. Safe to
        call multiple times. Wired into ``atexit`` from
        ``web/services/__init__.py`` so PKCS#11 sessions are released on
        process termination (Gap 6).
        """
        with self.__lock:
            for provider_id, backend in list(self.__backends.items()):
                try:
                    backend.close()
                except Exception:
                    logger.exception(
                        f"KMS.shutdown: backend.close() failed for provider {provider_id}"
                    )
            self.__backends.clear()
            self.__handle_cache.clear()

    # ── Key loading ──────────────────────────────────────────────────────────

    def load_key(self, key_id: int, token_password: str = None) -> None:
        """Load a key from KeyStorage and cache its handle.

        Dispatches to the matching :class:`CryptoBackend` for the row's
        provider. ``token_password`` is accepted for backwards
        compatibility but is no longer consulted — provider PINs are
        resolved through ``auth_secret_ref`` (kms-specs.md §7).
        """
        with self.__db.connection():
            record = self.__db.get_key_record(key_id)
        if not record:
            raise KeyError(f"KMS: key_id={key_id} not found in KeyStorage")

        provider_id = record.get("provider_id")
        storage_type = record.get("storage_type")

        if provider_id is not None:
            # CR-0004 decision 3: hard activation / mid-session failures
            # evict the cached backend so the next call re-runs
            # activation. ``backend.load_key`` may raise
            # ``KeyMissingOnToken`` (drift) — those propagate without
            # eviction since the slot is fine, just the key object is
            # gone.
            with self._evict_on_hard_failure(provider_id):
                backend = self._get_backend(provider_id)
                handle = backend.load_key(record)
            with self.__lock:
                self.__handle_cache[key_id] = handle
            logger.info(
                f"KMS: loaded key_id={key_id} via {type(backend).__name__} "
                f"(provider_id={provider_id}, storage_type={storage_type})"
            )
            return

        # No provider_id and no legacy fallback applies. The Phase 0.1
        # migration backfilled software rows; HSM rows from before the
        # provider model need an operator action: assign them to a
        # pkcs11 provider (UPDATE KeyStorage SET provider_id = X) or
        # delete and re-import via the management API.
        raise ValueError(
            f"KMS: key_id={key_id} (storage_type={storage_type}) has no provider_id. "
            f"Assign it to a pkcs11 provider or re-import via "
            f"POST /api/kms/keys/import."
        )

    def unload_key(self, key_id: int) -> None:
        """Remove a key handle from the in-memory cache."""
        with self.__lock:
            handle = self.__handle_cache.pop(key_id, None)
        if handle is None:
            return
        backend = self.__backends.get(handle.provider_id)
        if backend is not None:
            try:
                backend.unload_key(handle)
            except Exception:
                logger.exception(f"KMS: backend.unload_key failed for key_id={key_id}")
        logger.info(f"KMS: unloaded key_id={key_id}")

    def is_loaded(self, key_id: int) -> bool:
        return key_id in self.__handle_cache

    # ── Signing ──────────────────────────────────────────────────────────────

    def sign_digest(
        self,
        key_id: int,
        tbs_digest: bytes,
        signing_algorithm: str = None,
    ) -> bytes:
        """
        Sign a pre-computed digest. The key is loaded on first use and
        cached for subsequent calls. Returns the raw signature bytes.

        ``signing_algorithm`` is the CR-0003 token (`rsa-sha256`,
        `ecdsa-sha256`, …). It is forwarded to the backend so the
        correct mechanism is selected and so reserved-but-not-yet-wired
        tokens raise a typed ``UnsupportedSigningAlgorithm`` error
        before reaching the token. The digest's hash function must
        match the token (callers should produce it via
        ``signing_algorithm.hash_for_token``).

        When ``signing_algorithm`` is omitted, the legacy SHA-256-only
        behaviour is preserved — ``sign_data`` and a handful of
        utility callers still pass None. Those will be migrated as
        their callers grow algorithm awareness.

        Loading is serialised by ``self.__lock`` (double-checked) so two
        threads first-using the same key do not both run :meth:`load_key`
        — closes Gap 7. The actual signing is dispatched to the backend
        and runs without the KMS-level lock held; backends that need to
        serialise their own state (PKCS11Backend in particular) hold an
        internal lock.
        """
        handle = self.__handle_cache.get(key_id)
        if handle is None:
            with self.__lock:
                handle = self.__handle_cache.get(key_id)
                if handle is None:
                    self.load_key(key_id)
                    handle = self.__handle_cache[key_id]

        logger.debug(
            f"KMS: sign_digest key_id={key_id} signing_algorithm={signing_algorithm!r}"
        )
        # CR-0004 decision 3: a hard failure during sign — typically
        # surfaced when ``PKCS11Backend.sign_digest``'s single
        # reconnect attempt itself fails because the slot is gone or
        # the PIN has changed — evicts the cached backend so the next
        # signing attempt re-runs activation.
        with self._evict_on_hard_failure(handle.provider_id):
            backend = self._get_backend(handle.provider_id)
            return backend.sign_digest(
                handle, tbs_digest, signing_algorithm=signing_algorithm
            )

    def sign_data(self, key_id: int, data: bytes) -> bytes:
        """Hash data with SHA-256 then sign the digest.

        Legacy callsite; preserves the pre-CR-0003 SHA-256-only path for
        utility scripts that don't carry a signing_algorithm context.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return self.sign_digest(key_id, digest.finalize())

    # ── Key generation ───────────────────────────────────────────────────────

    def generate_key(
        self,
        algorithm: str,
        persist: bool = True,
        **kwargs
    ) -> dict:
        """
        Generate a cryptographic key.

        Parameters
        ----------
        algorithm : str
            Key algorithm. One of:
              Asymmetric — "RSA", "ECDSA", "Ed25519"
              Symmetric  — "AES"
        persist : bool
            If True (default) the key is stored in KeyStorage and the
            returned dict contains ``key_id``.
            If False the key material is returned in clear inside the dict
            and nothing is written to the database.
        **kwargs
            Algorithm-specific parameters:
              RSA   → key_size (int): 2048 | 3072 | 4096 | 8192
              ECDSA → curve (str):    "P-256" | "P-384" | "P-521"
              AES   → key_size (int): 128 | 192 | 256 | 512

        Returns
        -------
        dict
            Persisted:    {"key_id": int, "algorithm": str, ...metadata...}
            Not persisted: {"algorithm": str, "key_material": str, ...metadata...}
              - Asymmetric: key_material is PEM-encoded PKCS#8 private key,
                            public_key is PEM-encoded SubjectPublicKeyInfo
              - Symmetric:  key_material is base64-encoded raw key bytes (no public_key)
        """
        algo = algorithm.upper()

        if algo == "RSA":
            return self._generate_rsa(persist, **kwargs)
        elif algo == "ECDSA":
            return self._generate_ecdsa(persist, **kwargs)
        elif algo == "ED25519":
            return self._generate_ed25519(persist)
        elif algo == "AES":
            return self._generate_aes(persist, **kwargs)
        else:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                "Choose from: RSA, ECDSA, Ed25519, AES."
            )

    # ── RSA ──────────────────────────────────────────────────────────────────

    def _generate_rsa(self, persist: bool, key_size: int = 3072, **_) -> dict:
        key_size = int(key_size)
        if key_size not in _RSA_SIZES:
            raise ValueError(f"Invalid RSA key_size {key_size}. Choose from {sorted(_RSA_SIZES)}.")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        key_type = f"RSA-{key_size}"
        meta = {"algorithm": "RSA", "key_size": key_size}
        logger.info(f"KMS: generated {key_type}")
        return self._finalise(pem, "Plain", persist, meta, pub_pem, key_type)

    # ── ECDSA ─────────────────────────────────────────────────────────────────

    def _generate_ecdsa(self, persist: bool, curve: str = "P-256", **_) -> dict:
        if curve not in _EC_CURVES:
            raise ValueError(f"Invalid curve '{curve}'. Choose from {list(_EC_CURVES)}.")

        private_key = ec.generate_private_key(_EC_CURVES[curve])
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        key_type = f"ECDSA-{curve}"
        meta = {"algorithm": "ECDSA", "curve": curve}
        logger.info(f"KMS: generated {key_type}")
        return self._finalise(pem, "Plain", persist, meta, pub_pem, key_type)

    # ── Ed25519 ───────────────────────────────────────────────────────────────

    def _generate_ed25519(self, persist: bool) -> dict:
        private_key = ed25519.Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        key_type = "Ed25519"
        meta = {"algorithm": "Ed25519"}
        logger.info("KMS: generated Ed25519")
        return self._finalise(pem, "Plain", persist, meta, pub_pem, key_type)

    # ── AES ───────────────────────────────────────────────────────────────────

    def _generate_aes(self, persist: bool, key_size: int = 256, **_) -> dict:
        key_size = int(key_size)
        if key_size not in _AES_SIZES:
            raise ValueError(f"Invalid AES key_size {key_size}. Choose from {sorted(_AES_SIZES)}.")

        raw_key = os.urandom(key_size // 8)
        # Store symmetric keys as base64 in the private_key TEXT column
        b64_key = base64.b64encode(raw_key).decode()
        key_type = f"AES-{key_size}"
        meta = {"algorithm": "AES", "key_size": key_size}
        logger.info(f"KMS: generated {key_type}")
        return self._finalise_symmetric(b64_key, persist, meta, key_type)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _finalise(self, pem: str, storage_type: str, persist: bool, meta: dict,
                  public_key: str = None, key_type: str = None) -> dict:
        """Common finalisation for asymmetric keys.

        On persist, the PEM is encrypted at rest under the default crypto
        provider's KEK and stored as ``storage_type='Encrypted'``. The
        caller-supplied ``storage_type`` argument is preserved only for the
        non-default path (e.g. future symmetric flows).
        """
        if persist:
            with self.__db.connection():
                default_id = self.__db.get_default_provider_id()
                if default_id is None:
                    raise RuntimeError(
                        "KMS: no default crypto provider exists; cannot persist a "
                        "software key. Run reset_pki or apply migrations to seed "
                        "'software-default'."
                    )
                provider = self.__db.get_provider_by_id(default_id)
            try:
                kek = get_provider_kek(provider)
            except KEKUnavailable as e:
                raise RuntimeError(
                    f"KMS: cannot persist a software key under provider "
                    f"id={default_id} ('{provider.get('label')}'): {e}"
                )
            blob = encrypt_pem(pem.encode("utf-8"), kek)
            with self.__db.connection():
                key_id = self.__db.insert_key(
                    blob, "Encrypted", public_key, key_type,
                    provider_id=default_id,
                )
            logger.info(f"KMS: persisted encrypted key → KeyStorage id={key_id}")
            return {**meta, "key_id": key_id, "persisted": True}
        else:
            result = {**meta, "key_material": pem, "persisted": False}
            if public_key:
                result["public_key"] = public_key
            return result

    def _finalise_symmetric(self, b64_key: str, persist: bool, meta: dict,
                            key_type: str = None) -> dict:
        """Common finalisation for symmetric keys.

        Stored as ``storage_type='Symmetric'`` (Gap 11 fix) so the load
        path can reject a symmetric key being treated as an asymmetric
        signing key with a clear error rather than crashing the PEM parser.
        """
        if persist:
            with self.__db.connection():
                key_id = self.__db.insert_key(
                    b64_key, "Symmetric", public_key=None, key_type=key_type,
                )
            logger.info(f"KMS: persisted symmetric key → KeyStorage id={key_id}")
            return {**meta, "key_id": key_id, "persisted": True}
        else:
            return {**meta, "key_material": b64_key, "persisted": False}

    # ── Export ────────────────────────────────────────────────────────────────

    def export_key(self, key_id: int, password: bytes = None) -> bytes:
        """
        Export a key in PEM format, optionally encrypted with password.
        Planned for a future phase.
        """
        raise NotImplementedError("KMS.export_key is not yet implemented")
