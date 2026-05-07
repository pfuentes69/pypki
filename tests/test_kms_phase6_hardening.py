"""
Phase 6 — hardening + cleanup regressions.

Covers:
- Gap 9: ``hsm_token_id`` hex validation at the API boundary, not at sign
  time. ``import_pkcs11_key`` and ``PKCS11Backend.delete_key`` reject
  malformed values with ``ValueError`` and a useful message.
- Gap 11: AES keys persist as ``storage_type='Symmetric'`` and the
  asymmetric load path rejects them cleanly.
- Phase-6 KMS cleanup: HSM rows with no ``provider_id`` now raise
  ``ValueError`` pointing at the management API rather than silently
  routing through the deleted legacy ``KeyTools`` HSM path.
- ``PKCS11Helper`` requires an explicit ``lib_path`` (no ``PKCS11_LIB``
  default), since every legitimate caller sources it from
  ``CryptoProviders.module_path``.
"""
from __future__ import annotations

import pytest

from pypki.kms import KeyManagementService


# ── Gap 9: hsm_token_id hex validation ──────────────────────────────────────

@pytest.mark.parametrize("bad_hex", [
    "",            # empty
    "0",           # odd length
    "1z",          # non-hex chars
    "01 ",         # whitespace baked in
])
def test_import_pkcs11_key_rejects_invalid_hex(kms, fake_db, hsm_pin_kek, bad_hex):
    """Validation lives at the API boundary; a typo at import time fails
    fast with a clear ValueError instead of crashing inside PyKCS11 on
    first sign attempt."""
    fake_db.add_provider({
        "id": 1, "label": "p1", "kind": "pkcs11",
        "module_path": "/nope.so", "slot_label": "x",
        "auto_activate": True, "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}",
    })
    with pytest.raises(ValueError, match="hsm_token_id"):
        kms.import_pkcs11_key(1, bad_hex)


def test_validate_cka_id_hex_helper_round_trips():
    """Direct unit test on the helper. Even-length hex round-trips to bytes;
    invalid input raises with a useful message."""
    from pypki.backends.pkcs11 import _validate_cka_id_hex
    assert _validate_cka_id_hex("01") == b"\x01"
    assert _validate_cka_id_hex("ABcd") == b"\xab\xcd"
    with pytest.raises(ValueError, match="even number"):
        _validate_cka_id_hex("123")
    with pytest.raises(ValueError, match="not valid hex"):
        _validate_cka_id_hex("zz")
    with pytest.raises(ValueError, match="non-empty hex string"):
        _validate_cka_id_hex("")


# ── Gap 11: Symmetric storage_type ──────────────────────────────────────────

def test_aes_key_persists_with_symmetric_storage_type(kms, fake_db, hsm_pin_kek):
    """Generated AES keys land with ``storage_type='Symmetric'`` so the
    asymmetric load path can refuse them cleanly. Pre-Phase-6 they wrote
    ``'Plain'`` and crashed the PEM parser at load."""
    fake_db.add_provider({
        "id": 1, "label": "software-default", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}", "is_default": True,
    })
    result = kms.generate_key(algorithm="AES", key_size=256, persist=True)
    assert result["persisted"] is True
    row = fake_db.get_key_record(result["key_id"])
    assert row["storage_type"] == "Symmetric"


def test_load_rejects_symmetric_key_with_clear_message(kms, fake_db, hsm_pin_kek):
    """``KMS.sign_digest`` on a symmetric key fails with a clear
    "asymmetric load/sign path does not handle these" rather than
    crashing the PEM parser deep in cryptography."""
    pid = fake_db.add_provider({
        "id": 1, "label": "software-default", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}", "is_default": True,
    })
    aes = kms.generate_key(algorithm="AES", key_size=256, persist=True)
    with pytest.raises(ValueError, match="symmetric"):
        kms.sign_digest(aes["key_id"], b"\x00" * 32)


# ── Phase 6 KMS cleanup: no more legacy fallback ────────────────────────────

def test_hsm_row_without_provider_id_is_rejected_clearly(kms, fake_db, hsm_pin_kek):
    """Pre-Phase-6 a provider-less HSM row went through the legacy
    ``KeyTools`` path. That path is gone; the row now triggers a
    ``ValueError`` that names the recovery action."""
    key_id = fake_db.add_key({
        "storage_type": "HSM",
        "hsm_token_id": "aa",
        "provider_id": None,
        "key_type": "RSA-2048",
    })
    with pytest.raises(ValueError, match="provider_id"):
        kms.sign_digest(key_id, b"\x00" * 32)


# ── pkcs11_helper Phase 6 cleanup ────────────────────────────────────────────

def test_pkcs11_helper_requires_lib_path():
    """``PKCS11_LIB`` no longer exists; the constructor must demand a
    ``lib_path`` so every legitimate caller is sourcing it from
    ``CryptoProviders.module_path``."""
    from pypki.pkcs11_helper import PKCS11Helper
    with pytest.raises(ValueError, match="lib_path is required"):
        PKCS11Helper(lib_path="")
    with pytest.raises(ValueError, match="lib_path is required"):
        PKCS11Helper(lib_path=None)


def test_pkcs11_helper_dead_methods_are_actually_removed():
    """Sanity: the eight dead methods removed in Phase 6 must not return
    via a future regression. Listing them explicitly so adding one back
    has a forcing function."""
    from pypki.pkcs11_helper import PKCS11Helper
    removed = [
        "get_token_info",
        "get_objects",
        "get_certificates",
        "get_ca_certificates",
        "get_private_keys",
        "generate_private_key",
        "generate_csr",
        "export_public_key",
        "insert_certificate",
        "export_certificate",
        "export_private_key",
        "get_key_by_id",
    ]
    leftover = [m for m in removed if hasattr(PKCS11Helper, m)]
    assert leftover == [], (
        f"PKCS11Helper has unexpectedly grown {leftover} back; the "
        f"semantics belong on PKCS11Backend, not the session-lifecycle wrapper."
    )
