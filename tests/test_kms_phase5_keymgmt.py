"""
Phase 5a — provider CRUD + key management through the KMS.

Covers:
- ``KMS.generate_key_in_provider`` for software providers (sign+verify
  through the same path immediately after generation).
- ``KMS.delete_key`` happy path and in-use refusal.
- ``api_adapters`` provider create/update/delete validation: cross-field
  consistency, default-provider protection, has-keys protection.
- ``KMS.generate_key_in_provider`` + ``import_pkcs11_key`` against a real
  SoftHSM2 token (skipped when SoftHSM2 / pkcs11-tool / a token are not
  available).
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def _make_software_default(fake_db):
    return fake_db.add_provider({
        "label": "software-default",
        "kind": "software",
        "module_path": None,
        "slot_label": None,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}",
        "is_default": True,
    })


# ── Software-side generate / sign / delete (no HSM required) ─────────────────

def test_kms_generate_software_key_signs_and_verifies(kms, fake_db, hsm_pin_kek):
    """Generate a key through the KMS-aware flow, sign immediately with it,
    verify against the returned public key. Exercises the whole
    backend.generate_key → KeyStorage.insert → KMS dispatch chain."""
    provider_id = _make_software_default(fake_db)

    result = kms.generate_key_in_provider(
        provider_id, key_type="ECDSA-P-256", label="test-soft-1",
    )
    assert result["key_type"] == "ECDSA-P-256"
    assert result["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    key_id = result["key_id"]

    digest = _sha256(b"freshly-generated-key")
    sig = kms.sign_digest(key_id, digest)

    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pubkey = load_pem_public_key(result["public_key"].encode())
    pubkey.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def test_kms_generate_rsa3072_software_key(kms, fake_db, hsm_pin_kek):
    provider_id = _make_software_default(fake_db)
    result = kms.generate_key_in_provider(provider_id, key_type="RSA-3072")
    assert result["key_type"] == "RSA-3072"
    digest = _sha256(b"hello rsa-3072")
    sig = kms.sign_digest(result["key_id"], digest)
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pubkey = load_pem_public_key(result["public_key"].encode())
    pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))


def test_kms_generate_rejects_invalid_key_type(kms, fake_db, hsm_pin_kek):
    provider_id = _make_software_default(fake_db)
    with pytest.raises(ValueError, match="Unsupported key_type"):
        kms.generate_key_in_provider(provider_id, key_type="bogus")


def test_kms_delete_software_key_happy_path(kms, fake_db, hsm_pin_kek):
    provider_id = _make_software_default(fake_db)
    result = kms.generate_key_in_provider(provider_id, key_type="ECDSA-P-256")
    key_id = result["key_id"]
    assert fake_db.get_key_record(key_id) is not None
    out = kms.delete_key(key_id)
    assert out == {"deleted": True}
    assert fake_db.get_key_record(key_id) is None


def test_kms_delete_key_refuses_when_in_use(kms, fake_db, hsm_pin_kek):
    """If a CA / OCSP responder / cert references the key, delete_key
    returns ``{deleted: False, reason: in_use, usage: {...}}`` without
    touching anything. The route handler maps this to 409."""
    provider_id = _make_software_default(fake_db)
    result = kms.generate_key_in_provider(provider_id, key_type="ECDSA-P-256")
    key_id = result["key_id"]

    fake_db._usage_overrides = {key_id: {"cas": 1, "ocsp_responders": 0, "certificates": 0}}
    out = kms.delete_key(key_id)
    assert out["deleted"] is False
    assert out["reason"] == "in_use"
    assert out["usage"]["cas"] == 1
    assert fake_db.get_key_record(key_id) is not None  # untouched


def test_kms_delete_unknown_key(kms, fake_db, hsm_pin_kek):
    _make_software_default(fake_db)
    assert kms.delete_key(999) is None


# ── Provider create / update / delete via api_adapters ──────────────────────

def test_create_provider_validates_kind(fake_db, hsm_pin_kek, monkeypatch):
    """``kind`` is required and must be 'software' or 'pkcs11'."""
    monkeypatch.setattr("pypki.core.PyPKI", lambda *a, **k: None)
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))

    with pytest.raises(ValueError, match="kind must be"):
        A.create_crypto_provider({"label": "x", "kind": "junk"})


def test_create_pkcs11_requires_module_path(fake_db, hsm_pin_kek, monkeypatch):
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    with pytest.raises(ValueError, match="module_path is required"):
        A.create_crypto_provider({
            "label": "luna-x", "kind": "pkcs11",
            "auto_activate": False, "auth_secret_ref": "operator:prompt",
        })


def test_create_db_encrypted_requires_pin(fake_db, hsm_pin_kek, monkeypatch):
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    with pytest.raises(ValueError, match="requires a 'pin'"):
        A.create_crypto_provider({
            "label": "soft-1", "kind": "software",
            "auto_activate": True, "auth_secret_ref": "db:encrypted",
        })


def test_create_db_encrypted_round_trip(fake_db, hsm_pin_kek, monkeypatch):
    """db:encrypted creation encrypts the supplied PIN and stores the blob;
    a later resolve_provider_secret can recover it under the master KEK."""
    from web.services import api_adapters as A
    from pypki.key_encryption import resolve_provider_secret
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))

    new_id = A.create_crypto_provider({
        "label": "soft-encrypted", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "db:encrypted",
        "pin": "operator-chosen-pin-9876",
    })
    record = fake_db.get_provider_by_id(new_id)
    assert record is not None
    # The plaintext PIN is *not* persisted.
    assert "pin" not in record
    assert record["auth_secret_blob"] is not None
    # The blob decrypts back to the original PIN under the master KEK.
    assert resolve_provider_secret(record) == b"operator-chosen-pin-9876"


def test_update_provider_changes_auto_activate_emits_audit(fake_db, hsm_pin_kek, monkeypatch):
    """Toggling auto_activate is recorded as a separate audit event so it
    is reviewable independently of generic UPDATE entries."""
    from web.services import api_adapters as A
    pki_stub = _StubPki(fake_db)
    monkeypatch.setattr(A, "pki", pki_stub)

    audits = []
    monkeypatch.setattr(A, "write_audit_log", lambda *a, **k: audits.append(a))

    pid = fake_db.add_provider({
        "label": "p1", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}",
    })
    A.update_crypto_provider(pid, {
        "auto_activate": False, "auth_secret_ref": "operator:prompt",
    })
    actions = [a[2] for a in audits]
    assert "UPDATE" in actions
    assert "AUTO_ACTIVATE_TOGGLED" in actions


def test_delete_provider_refuses_default(fake_db, hsm_pin_kek, monkeypatch):
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    pid = _make_software_default(fake_db)
    out = A.delete_crypto_provider(pid)
    assert out and out["deleted"] is False and out["reason"] == "is_default"


def test_delete_provider_refuses_when_keys_present(fake_db, hsm_pin_kek, monkeypatch):
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    pid = fake_db.add_provider({
        "label": "p2", "kind": "software", "auto_activate": True,
        "auth_secret_ref": "env:HSM_PIN_KEK", "extra_json": "{}",
    })
    fake_db.add_key({"provider_id": pid, "storage_type": "Encrypted", "key_type": "RSA-2048"})
    out = A.delete_crypto_provider(pid)
    assert out["deleted"] is False
    assert out["reason"] == "has_keys"
    assert out["key_count"] == 1


def test_delete_provider_happy_path(fake_db, hsm_pin_kek, monkeypatch):
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    pid = fake_db.add_provider({
        "label": "p3", "kind": "software", "auto_activate": True,
        "auth_secret_ref": "env:HSM_PIN_KEK", "extra_json": "{}",
    })
    out = A.delete_crypto_provider(pid)
    assert out["deleted"] is True
    assert fake_db.get_provider_by_id(pid) is None


# ── PKCS#11 generate / import / delete (live SoftHSM2) ──────────────────────

def test_kms_pkcs11_generate_sign_delete_round_trip(
    kms, fake_db, softhsm_token, monkeypatch,
):
    """Generate an RSA-2048 key on the SoftHSM token through the KMS;
    sign+verify against the public key returned by the backend; delete
    the key (which removes both on-token objects). End-to-end provider
    model + Phase 5a generate/delete on real hardware-emulator."""
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-test-gen",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    result = kms.generate_key_in_provider(
        provider_id, key_type="RSA-2048", label="kms-phase5-gen",
    )
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pubkey = load_pem_public_key(result["public_key"].encode())

        digest = _sha256(b"on-token-generated")
        sig = kms.sign_digest(result["key_id"], digest)
        pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    finally:
        out = kms.delete_key(result["key_id"])
        assert out and out["deleted"] is True


def test_kms_pkcs11_import_existing_token_key(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """Generate a key on the token via pkcs11-tool (the softhsm_rsa_key
    fixture), then import it through the KMS API. The imported row signs
    correctly and the public key matches the one read off the token."""
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-test-import",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    hex_id, token_pub_der = softhsm_rsa_key
    result = kms.import_pkcs11_key(provider_id, hex_id, label="imported-1")
    assert result["label"] == "imported-1"
    assert result["hsm_token_id"] == hex_id
    assert result["key_type"] == "RSA-2048"
    # Public key from the import path matches what pkcs11-tool reads off the
    # token (DER input vs PEM output, so reload to canonicalise).
    from cryptography.hazmat.primitives.serialization import (
        load_der_public_key, load_pem_public_key,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    expected = load_der_public_key(token_pub_der).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    assert result["public_key"].strip() == expected.strip()

    digest = _sha256(b"imported-key-sign")
    sig = kms.sign_digest(result["key_id"], digest)
    load_pem_public_key(result["public_key"].encode()).verify(
        sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256())
    )


def test_kms_delete_imported_key_preserves_on_token_objects(
    kms, fake_db, softhsm_token, softhsm_rsa_key, softhsm_pkcs11_tool, monkeypatch,
):
    """Deleting an imported key removes the pyPKI registration but leaves
    the on-token objects in place — the operator created them out-of-band
    and pyPKI must not unilaterally destroy them."""
    import subprocess
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-test-import-delete",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    hex_id, _ = softhsm_rsa_key
    imported = kms.import_pkcs11_key(provider_id, hex_id, label=None)
    # Imported keys must carry key_owned=False so delete is non-destructive.
    row = fake_db.get_key_record(imported["key_id"])
    assert row.get("key_owned") is False

    out = kms.delete_key(imported["key_id"])
    assert out == {"deleted": True}

    # Verify the on-token objects still exist.
    listing = subprocess.run(
        [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
         "--login", "--pin", pin, "--list-objects"],
        check=True, capture_output=True, text=True,
    ).stdout
    assert f"ID:         {int(hex_id, 16)} ({hex(int(hex_id, 16))})" in listing or hex_id in listing.lower(), (
        f"Expected CKA_ID {hex_id} to still be on the token after import-delete; got:\n{listing}"
    )


def test_kms_delete_generated_key_destroys_on_token_objects(
    kms, fake_db, softhsm_token, softhsm_pkcs11_tool, monkeypatch,
):
    """A key pyPKI generated *is* owned (key_owned=TRUE); deletion cascades
    to the on-token objects. The complementary case to the import test."""
    import subprocess
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-test-gen-delete",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    gen = kms.generate_key_in_provider(
        provider_id, key_type="RSA-2048", label="phase5-owned-delete",
    )
    row = fake_db.get_key_record(gen["key_id"])
    assert row.get("key_owned") is True
    cka_id = gen["hsm_token_id"]

    out = kms.delete_key(gen["key_id"])
    assert out == {"deleted": True}

    # The on-token objects must be gone.
    listing = subprocess.run(
        [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
         "--login", "--pin", pin, "--list-objects"],
        check=True, capture_output=True, text=True,
    ).stdout
    assert cka_id not in listing.lower(), (
        f"Generated key CKA_ID {cka_id} should have been destroyed on delete; "
        f"still present in:\n{listing}"
    )


def test_kms_pkcs11_import_inherits_token_label_when_unset(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """When the operator does not supply a label, the imported row carries
    the token's CKA_LABEL so identity isn't silently dropped on import.
    Regression for the user-reported gap: empty label → row showed no label."""
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-test-import-fallback",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    hex_id, _ = softhsm_rsa_key
    # Confirm the on-token CKA_LABEL the fixture sets — the assertion below
    # depends on this contract.
    expected_label = f"pypki-test-rsa-{hex_id}"

    result = kms.import_pkcs11_key(provider_id, hex_id, label=None)
    assert result["label"] == expected_label

    # The KeyStorage row carries the inherited label too.
    row = fake_db.get_key_record(result["key_id"])
    assert row["label"] == expected_label


# ── Helpers ───────────────────────────────────────────────────────────────────

class _StubPki:
    """Drop-in stand-in for the module-level ``pki`` PyPKI singleton in
    api_adapters. Exposes only the surface those adapters touch."""
    def __init__(self, db):
        self._db = db
        from pypki.kms import KeyManagementService
        self._kms = KeyManagementService(db)

    def get_db(self):
        return self._db

    def get_kms(self):
        return self._kms

    def get_config_value(self, key, default=None):
        return default
