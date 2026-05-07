"""
Crypto backends — the layer between KeyManagementService and the actual
key material.

The KMS dispatches signing/loading operations to one of two sibling
backends based on the CryptoProviders row's ``kind``:

- :class:`SoftwareBackend` — libcrypto in-process; PEMs encrypted at rest
  under a per-provider KEK derived from the provider's PIN.
- :class:`PKCS11Backend` — a PKCS#11 token (SoftHSM2 / Luna / YubiHSM /
  cloud HSM); one shared session per provider.

See :doc:`../doc/kms-strategy.md` §3 (architecture), §5 (backend contract),
§6 (activation lifecycle).
"""
from .base import CryptoBackend, KeyHandle, BackendError, BackendNotActive
from .software import SoftwareBackend
from .pkcs11 import PKCS11Backend

__all__ = [
    "CryptoBackend",
    "KeyHandle",
    "BackendError",
    "BackendNotActive",
    "SoftwareBackend",
    "PKCS11Backend",
]
