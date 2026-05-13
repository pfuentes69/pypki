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


# ── CR-0002 §18.1: software key export ────────────────────────────────────────

def test_export_software_rsa_key_round_trip(kms, fake_db, hsm_pin_kek):
    """Round-trip a software RSA-3072 key through the export path: load
    the returned PEM with the same passphrase and assert that a fresh
    signature on the reloaded key verifies against the in-DB public key.
    Closes the happy-path acceptance criterion in CR-0002."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key,
    )
    from cryptography.hazmat.primitives.asymmetric import padding
    provider_id = _make_software_default(fake_db)
    gen = kms.generate_key_in_provider(
        provider_id, key_type="RSA-3072", label="export-target",
    )
    key_id = gen["key_id"]

    passphrase = b"correct-horse-battery-staple"
    pem = kms.export_software_key(key_id, passphrase)
    assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    # Wrong passphrase fails to decrypt — basic sanity that the wrap
    # uses the supplied passphrase, not an empty / hard-coded one.
    with pytest.raises(Exception):
        load_pem_private_key(pem, password=b"wrong-passphrase-9999")

    reloaded = load_pem_private_key(pem, password=passphrase)
    digest = _sha256(b"export-round-trip")
    sig = reloaded.sign(digest, padding.PKCS1v15(),
                        Prehashed(hashes.SHA256()))
    load_pem_public_key(gen["public_key"].encode()).verify(
        sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()),
    )


def test_export_software_ecdsa_key_round_trip(kms, fake_db, hsm_pin_kek):
    """Same round-trip as the RSA case, exercising the ECDSA path through
    BestAvailableEncryption's PBES2 wrapping."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key,
    )
    provider_id = _make_software_default(fake_db)
    gen = kms.generate_key_in_provider(
        provider_id, key_type="ECDSA-P-256", label="export-target-ec",
    )
    passphrase = b"correct-horse-battery-staple"
    pem = kms.export_software_key(gen["key_id"], passphrase)
    assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    reloaded = load_pem_private_key(pem, password=passphrase)
    digest = _sha256(b"export-round-trip-ec")
    sig = reloaded.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    load_pem_public_key(gen["public_key"].encode()).verify(
        sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())),
    )


def test_export_refuses_hsm_key(kms, fake_db, hsm_pin_kek):
    """HSM-backed keys are non-extractable by §8.2 policy — the export
    path must refuse with PermissionError (which the route maps to 409)
    so direct API callers cannot side-step the policy."""
    provider_id = fake_db.add_provider({
        "label": "software-default",
        "kind": "software",
        "module_path": None, "slot_label": None,
        "auth_kind": "pin", "auto_activate": True,
        "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}", "is_default": True,
    })
    # Synthesise an HSM row directly in the fake DB so we don't need a
    # real PKCS#11 fixture for the policy check.
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "public_key": "-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----",
        "key_type": "RSA-2048",
        "hsm_token_id": "deadbeef",
        "key_owned": True,
        "private_key": None,
    })
    with pytest.raises(PermissionError) as exc_info:
        kms.export_software_key(key_id, b"a-strong-passphrase")
    assert "HSM" in str(exc_info.value) or "non-extractable" in str(exc_info.value)


def test_export_refuses_imported_software_key(kms, fake_db, hsm_pin_kek):
    """``key_owned=FALSE`` means the operator brought the material in;
    pyPKI is not a re-export channel for it. Must refuse with
    PermissionError → 409 at the route layer."""
    provider_id = _make_software_default(fake_db)
    # Generate a normal key, then flip key_owned to simulate the "imported
    # via a future software-import path" case (the export rule applies
    # regardless of how the row got into KeyStorage).
    gen = kms.generate_key_in_provider(
        provider_id, key_type="ECDSA-P-256", label="imported-software",
    )
    fake_db.keys[gen["key_id"]]["key_owned"] = False
    with pytest.raises(PermissionError) as exc_info:
        kms.export_software_key(gen["key_id"], b"a-strong-passphrase")
    assert "imported" in str(exc_info.value) or "re-export" in str(exc_info.value)


def test_export_rejects_short_passphrase(kms, fake_db, hsm_pin_kek):
    """The 12-character minimum is enforced at the KMS layer so direct
    callers can't side-step the route-layer length check."""
    provider_id = _make_software_default(fake_db)
    gen = kms.generate_key_in_provider(
        provider_id, key_type="RSA-3072", label="short-passphrase",
    )
    with pytest.raises(ValueError):
        kms.export_software_key(gen["key_id"], b"too-short")


def test_export_unknown_key_raises_key_error(kms, fake_db, hsm_pin_kek):
    _make_software_default(fake_db)
    with pytest.raises(KeyError):
        kms.export_software_key(99999, b"a-strong-passphrase")


def test_export_adapter_writes_audit_row(fake_db, hsm_pin_kek, monkeypatch):
    """``export_kms_key`` (adapter) writes ``EXPORT`` on success and
    ``EXPORT_REFUSED_HSM`` / ``EXPORT_REFUSED_IMPORTED`` on the matching
    refusals so the details-page audit panel records *why* the export
    was blocked, not just that it failed."""
    from web.services import api_adapters as A
    captured: list[tuple] = []
    def _capture(resource_type, resource_id, action, user_id=0):
        captured.append((resource_type, resource_id, action, user_id))
    monkeypatch.setattr(A, "write_audit_log", _capture)
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))

    provider_id = _make_software_default(fake_db)
    gen = A.generate_kms_key(provider_id=provider_id, key_type="ECDSA-P-256",
                             label="audit-export", user_id=7)
    key_id = gen["key_id"]

    # 1. Successful export → EXPORT.
    captured.clear()
    A.export_kms_key(key_id, "correct-horse-battery", user_id=7)
    assert any(c[2] == "EXPORT" and c[1] == key_id and c[3] == 7
               for c in captured), captured

    # 2. HSM refusal → EXPORT_REFUSED_HSM. Synthesise an HSM row.
    captured.clear()
    hsm_key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "public_key": "-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----",
        "key_type": "RSA-2048", "hsm_token_id": "cafebabe",
        "key_owned": True, "private_key": None,
    })
    with pytest.raises(PermissionError):
        A.export_kms_key(hsm_key_id, "correct-horse-battery", user_id=7)
    assert any(c[2] == "EXPORT_REFUSED_HSM" and c[1] == hsm_key_id
               for c in captured), captured

    # 3. Imported software refusal → EXPORT_REFUSED_IMPORTED.
    captured.clear()
    imp = A.generate_kms_key(provider_id=provider_id, key_type="RSA-3072",
                             label="imp", user_id=7)
    fake_db.keys[imp["key_id"]]["key_owned"] = False
    with pytest.raises(PermissionError):
        A.export_kms_key(imp["key_id"], "correct-horse-battery", user_id=7)
    assert any(c[2] == "EXPORT_REFUSED_IMPORTED" and c[1] == imp["key_id"]
               for c in captured), captured


# ── CR-0005: structured backend-error body ────────────────────────────────────

def test_backend_error_body_key_missing_on_token_carries_recovery_url():
    """When ``KeyMissingOnToken`` carries a ``key_id``, the structured
    503 body advertises a ``recovery`` URL pointing at the key details
    page so the operator has a clickable next step. The Flask error
    handler (CR-0005) wraps this with the response."""
    from pypki.backends.base import KeyMissingOnToken
    from web.routes.main_routes import _build_backend_error_body

    e = KeyMissingOnToken("private key missing", key_id=42, provider_id=3)
    body, code = _build_backend_error_body(e)
    assert code == "key_missing_on_token"
    assert body["key_id"] == 42
    assert body["provider_id"] == 3
    assert body["recovery"] == "/key_details.html?id=42"
    assert "missing on the HSM" in body["description"]


def test_backend_error_body_slot_not_found_no_recovery_url():
    """``SlotNotFound`` typically carries ``provider_id`` (the activation
    classifier sets it) but not ``key_id`` (the slot is gone, the failure
    is upstream of any specific key). The structured body still carries
    `provider_id`; ``recovery`` is omitted because there is no
    per-key page to point at."""
    from pypki.backends.base import SlotNotFound
    from web.routes.main_routes import _build_backend_error_body

    e = SlotNotFound("slot gone", provider_id=7)
    body, code = _build_backend_error_body(e)
    assert code == "slot-missing"
    assert body["provider_id"] == 7
    assert body["key_id"] is None
    assert "recovery" not in body
    assert "configured slot" in body["description"]


def test_backend_error_body_auth_and_module_failures_classified():
    """``AuthenticationFailed`` and ``ModuleLoadFailed`` map to distinct
    codes so the UI can render specific copy (token-reinitialised vs
    misconfigured module_path) instead of conflating them."""
    from pypki.backends.base import AuthenticationFailed, ModuleLoadFailed
    from web.routes.main_routes import _build_backend_error_body

    body_auth, code_auth = _build_backend_error_body(
        AuthenticationFailed("PIN rejected", provider_id=2)
    )
    assert code_auth == "auth-failed"
    assert "reinitialised with a new PIN" in body_auth["description"]

    body_mod, code_mod = _build_backend_error_body(
        ModuleLoadFailed("dlopen failed", provider_id=2)
    )
    assert code_mod == "module-error"
    assert "library could not be loaded" in body_mod["description"]


def test_crl_scheduler_skips_drifted_ca_with_typed_log(monkeypatch, caplog):
    """The background ``generate_crls`` pass logs a structured WARN
    naming the failure class + key_id + provider_id when a CA's bound
    key has drifted, then continues to the next CA — the whole pass
    must not abort on a single failing signer (CR-0005 step 4)."""
    import logging
    import web.services as services_mod
    from pypki.backends.base import KeyMissingOnToken

    cas = [
        {"id": 5, "name": "Drifted CA"},
        {"id": 6, "name": "Healthy CA"},
    ]
    calls: list[int] = []

    class _CrlBytes:
        def public_bytes(self, _encoding):
            return b"-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"

    def _fake_generate_crl(ca_id):
        calls.append(ca_id)
        if ca_id == 5:
            raise KeyMissingOnToken("key gone", key_id=99, provider_id=3)
        return _CrlBytes()

    monkeypatch.setattr(services_mod.pki, "get_ca_collection", lambda: cas)
    monkeypatch.setattr(services_mod.pki, "generate_crl", _fake_generate_crl)
    # Stub the CRL file writes so the assertion is about behaviour,
    # not filesystem state.
    import io
    real_open = open
    def _fake_open(path, mode="r", *a, **kw):
        if "b" in mode and "w" in mode:
            return io.BytesIO()
        return real_open(path, mode, *a, **kw)
    monkeypatch.setattr("builtins.open", _fake_open)

    caplog.set_level(logging.WARNING, logger="pypki.log")
    services_mod.generate_crls()

    # Both CAs were visited — the failing one did not abort the pass.
    assert calls == [5, 6]
    # The log line names the typed exception class and the metadata.
    msg = " ".join(rec.getMessage() for rec in caplog.records)
    assert "KeyMissingOnToken" in msg
    assert "Drifted CA" in msg
    assert "key_id=99" in msg
    assert "provider_id=3" in msg


# ── Helpers ───────────────────────────────────────────────────────────────────

class _StubPki:
    """Drop-in stand-in for the module-level ``pki`` PyPKI singleton in
    api_adapters. Exposes only the surface those adapters touch.

    Pass an external ``kms`` (typically the ``kms`` fixture from conftest)
    to inherit its teardown — without that, PKCS#11 sessions opened
    during the test leak between cases and the next SoftHSM login fails
    with ``CKR_USER_ALREADY_LOGGED_IN``.
    """
    def __init__(self, db, kms=None):
        self._db = db
        if kms is None:
            from pypki.kms import KeyManagementService
            kms = KeyManagementService(db)
        self._kms = kms

    def get_db(self):
        return self._db

    def get_kms(self):
        return self._kms

    def get_config_value(self, key, default=None):
        return default


# ── CR-0001 §18.1: merged token-aware key listing ─────────────────────────────

def test_list_kms_keys_no_provider_returns_envelope_with_db_rows_only(
    fake_db, hsm_pin_kek, monkeypatch,
):
    """Without a ``provider_id`` filter the adapter returns DB rows across
    every provider, every row marked ``registered_and_present``; the
    envelope flags token enumeration as not-attempted
    (``reason='no_provider_scope'``). Closes the global-listing branch of
    step 2 in CR-0001's action plan."""
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    provider_id = _make_software_default(fake_db)
    A.generate_kms_key(provider_id=provider_id, key_type="ECDSA-P-256",
                       label="k1", user_id=0)

    out = A.list_kms_keys()
    assert isinstance(out, dict)
    assert out["token_enumeration"] == {
        "available": False, "reason": "no_provider_scope",
    }
    assert len(out["keys"]) == 1
    row = out["keys"][0]
    assert row["state"] == "registered_and_present"
    assert row["unimportable_reason"] is None


def test_list_kms_keys_software_provider_marks_not_applicable(
    fake_db, hsm_pin_kek, monkeypatch,
):
    """Scoped to a software provider, the merged listing returns DB rows
    only — there is no parallel store to enumerate — and the envelope
    surfaces ``reason='not_applicable'`` so the UI knows not to render the
    "token enumeration unavailable" banner."""
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    provider_id = _make_software_default(fake_db)
    A.generate_kms_key(provider_id=provider_id, key_type="RSA-3072",
                       label="sw-key", user_id=0)

    out = A.list_kms_keys(provider_id=provider_id)
    assert out["token_enumeration"] == {
        "available": False, "reason": "not_applicable",
    }
    assert len(out["keys"]) == 1
    assert out["keys"][0]["state"] == "registered_and_present"


def test_list_kms_keys_pkcs11_merges_registered_and_present_only(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """For a pkcs11 provider, the merged listing combines:

    - the imported key (``registered_and_present``), and
    - any on-token key that pyPKI has never seen (``present_only`` with
      ``unimportable_reason=None`` — importable by clicking Import).

    Exercises the happy-path merge after step 1 + step 2 lands.
    """
    from web.services import api_adapters as A
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    pki_stub = _StubPki(fake_db, kms=kms)
    monkeypatch.setattr(A, "pki", pki_stub)

    provider_id = fake_db.add_provider({
        "label": "softhsm-merged-list",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    # Import the fixture-generated key so it becomes registered_and_present.
    hex_id, _ = softhsm_rsa_key
    imported = pki_stub.get_kms().import_pkcs11_key(
        provider_id, hex_id, label="merged-listing-imported",
    )

    # Generate a second on-token key directly through pyPKI; this one is
    # also registered.
    second = pki_stub.get_kms().generate_key_in_provider(
        provider_id, key_type="ECDSA-P-256", label="merged-listing-gen",
    )

    out = A.list_kms_keys(provider_id=provider_id)
    assert out["token_enumeration"]["available"] is True
    assert out["token_enumeration"]["reason"] is None

    by_token = {k["hsm_token_id"]: k for k in out["keys"] if k.get("hsm_token_id")}
    assert imported["hsm_token_id"] in by_token
    assert second["hsm_token_id"] in by_token
    assert by_token[imported["hsm_token_id"]]["state"] == "registered_and_present"
    assert by_token[second["hsm_token_id"]]["state"] == "registered_and_present"
    # Both came back with id set (they are KeyStorage rows).
    assert by_token[imported["hsm_token_id"]]["id"] == imported["key_id"]


def test_list_kms_keys_pkcs11_present_only_row_for_unregistered_token_key(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """An on-token key that has *not* been imported into pyPKI appears in
    the listing as ``state="present_only"`` with ``id=null`` and the
    backend's ``unimportable_reason`` (``None`` for a healthy paired key)."""
    from web.services import api_adapters as A
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    monkeypatch.setattr(A, "pki", _StubPki(fake_db, kms=kms))

    provider_id = fake_db.add_provider({
        "label": "softhsm-present-only",
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
    # Deliberately do NOT call import_pkcs11_key — the key exists on the
    # token only.

    out = A.list_kms_keys(provider_id=provider_id)
    assert out["token_enumeration"]["available"] is True

    by_token = {k["hsm_token_id"]: k for k in out["keys"] if k.get("hsm_token_id")}
    assert hex_id in by_token, (
        f"present_only row missing for unregistered token key {hex_id}; "
        f"got {list(by_token)}"
    )
    row = by_token[hex_id]
    assert row["state"] == "present_only"
    assert row["id"] is None
    assert row["usage"] is None
    assert row["unimportable_reason"] is None
    assert row["key_type"] == "RSA-2048"
    assert row["public_key"] is not None


def test_get_kms_key_returns_named_usage_items_and_provider_label(
    fake_db, hsm_pin_kek, monkeypatch,
):
    """``get_kms_key`` returns the named dependents (``usage.items``), not
    just a count, and resolves the bound provider's label so the details
    page can render the provider chip without a second round-trip. Step 3
    of CR-0001's action plan (kms-specs.md §18.1)."""
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    provider_id = _make_software_default(fake_db)
    result = A.generate_kms_key(provider_id=provider_id,
                                key_type="ECDSA-P-256",
                                label="details-test", user_id=0)
    key_id = result["key_id"]

    # Inject named dependents so we can assert the new shape end-to-end.
    fake_db._usage_items = {key_id: [
        {"type": "ca", "id": 7, "name": "Acme Issuing"},
        {"type": "certificate", "id": 42, "name": "svc.acme.ch", "ca_id": 7},
        {"type": "ocsp_responder", "id": 1, "name": "Acme OCSP Responder"},
    ]}

    detail = A.get_kms_key(key_id)
    assert detail is not None
    assert detail["state"] == "registered_and_present"
    assert detail["provider_label"] == "software-default"

    usage = detail["usage"]
    assert usage["count"] == 3
    names = [it["name"] for it in usage["items"]]
    assert "Acme Issuing" in names
    assert "svc.acme.ch" in names
    assert "Acme OCSP Responder" in names
    # CA reference on the certificate item flows through.
    cert_item = next(it for it in usage["items"] if it["type"] == "certificate")
    assert cert_item["ca_id"] == 7
    # No private material leaks.
    assert "private_key" not in detail
    assert "token_password" not in detail


def test_get_kms_key_probes_hsm_and_flips_state_on_drift(
    kms, fake_db, softhsm_token, softhsm_rsa_key, softhsm_pkcs11_tool, monkeypatch,
):
    """``GET /api/kms/keys/{id}`` runs an on-demand probe against the
    token. If the on-token object has been deleted out-of-band, the
    response carries ``state="registered_only"`` and a
    ``token_check.available=True, present=False`` envelope so the
    details page can render a clear "missing on the HSM" banner."""
    import subprocess
    from web.services import api_adapters as A
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    pki_stub = _StubPki(fake_db, kms=kms)
    monkeypatch.setattr(A, "pki", pki_stub)

    provider_id = fake_db.add_provider({
        "label": "softhsm-drift-detail",
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
    imported = kms.import_pkcs11_key(provider_id, hex_id, label="drift-target")

    # Sanity: while the on-token object exists, the details endpoint
    # reports it as present and the row state is registered_and_present.
    before = A.get_kms_key(imported["key_id"])
    assert before["state"] == "registered_and_present"
    assert before["token_check"]["available"] is True
    assert before["token_check"]["present"] is True

    # Delete the on-token object out-of-band — pyPKI is unaware.
    for obj_type in ("privkey", "pubkey"):
        subprocess.run(
            [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
             "--login", "--pin", pin,
             "--delete-object", "--type", obj_type, "--id", hex_id],
            capture_output=True, text=True,
        )

    after = A.get_kms_key(imported["key_id"])
    assert after["state"] == "registered_only", after
    assert after["token_check"] == {
        "available": True, "present": False, "reason": None,
    }


def test_sign_digest_raises_typed_error_when_key_missing_on_token(
    kms, fake_db, softhsm_token, softhsm_rsa_key, softhsm_pkcs11_tool, monkeypatch,
):
    """Signing a key whose on-token object has been deleted out-of-band
    raises :class:`KeyMissingOnToken` rather than a bare ``RuntimeError``.
    Lets higher-level callers (CA issuance, OCSP, CRL generation) distinguish
    "this key has drifted" from other backend failures and render a clean
    user-facing error."""
    import subprocess
    from pypki.backends.base import KeyMissingOnToken

    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    provider_id = fake_db.add_provider({
        "label": "softhsm-drift-sign",
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
    imported = kms.import_pkcs11_key(provider_id, hex_id, label="sign-drift-target")

    # Delete the on-token objects, then try to sign — load_key must fail
    # with the typed exception.
    for obj_type in ("privkey", "pubkey"):
        subprocess.run(
            [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
             "--login", "--pin", pin,
             "--delete-object", "--type", obj_type, "--id", hex_id],
            capture_output=True, text=True,
        )

    digest = _sha256(b"drift-sign-attempt")
    with pytest.raises(KeyMissingOnToken):
        kms.sign_digest(imported["key_id"], digest)


def test_get_kms_key_unknown_returns_none(fake_db, hsm_pin_kek, monkeypatch):
    """Unknown id maps to ``None`` so the route handler can produce a 404
    without crashing on the new envelope shape."""
    from web.services import api_adapters as A
    monkeypatch.setattr(A, "pki", _StubPki(fake_db))
    _make_software_default(fake_db)
    assert A.get_kms_key(99999) is None


def test_list_kms_keys_pkcs11_surfaces_duplicate_cka_ids(
    kms, fake_db, softhsm_token, softhsm_pkcs11_tool, monkeypatch,
):
    """SoftHSM2 (and the PKCS#11 spec generally) allows multiple objects to
    share a ``CKA_ID``. The merged listing must surface every on-token
    private key, not collapse them. Second-and-subsequent entries with the
    same CKA_ID get ``unimportable_reason="duplicate_cka_id"`` so the
    operator sees the collision but cannot mis-import a duplicate.

    Regression for the user-reported bug where a token with four private
    keys at CKA_ID=02 (one registered + three pkcs11-tool-created)
    surfaced only one row in ``/kms_keys.html``."""
    import secrets
    import subprocess
    from web.services import api_adapters as A

    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    monkeypatch.setattr(A, "pki", _StubPki(fake_db, kms=kms))

    provider_id = fake_db.add_provider({
        "label": "softhsm-duplicate-cka",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    # Pick a CKA_ID unlikely to clash with anything else in the slot,
    # then create *three* RSA keys with the same CKA_ID via pkcs11-tool.
    shared_id = secrets.token_hex(4)
    labels = [f"dup-{shared_id}-{i}" for i in range(3)]
    for lbl in labels:
        subprocess.run(
            [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
             "--login", "--pin", pin,
             "--keypairgen", "--key-type", "rsa:2048",
             "--label", lbl, "--id", shared_id],
            check=True, capture_output=True, text=True,
        )

    try:
        out = A.list_kms_keys(provider_id=provider_id)
        assert out["token_enumeration"]["available"] is True

        matching = [k for k in out["keys"] if k.get("hsm_token_id") == shared_id]
        # All three on-token objects must surface, not just one.
        assert len(matching) == 3, (
            f"Expected three rows for shared CKA_ID={shared_id}, got "
            f"{len(matching)}: {matching}"
        )

        # None of them are registered in pyPKI, so the first is importable
        # (Not registered) and the other two are duplicate_cka_id read-only.
        reasons = sorted([k["unimportable_reason"] or "" for k in matching])
        assert reasons == ["", "duplicate_cka_id", "duplicate_cka_id"], reasons

        # Every duplicate row carries its own label so the operator can
        # tell them apart for cleanup.
        rendered_labels = {k["label"] for k in matching}
        assert rendered_labels == set(labels)
    finally:
        # pkcs11-tool --delete-object removes one object per call, so loop
        # N times for each object class (N + 1 to also reap any leftover
        # from prior failed runs of this test).
        for _ in range(len(labels) + 1):
            for obj_type in ("privkey", "pubkey"):
                subprocess.run(
                    [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
                     "--login", "--pin", pin,
                     "--delete-object", "--type", obj_type, "--id", shared_id],
                    capture_output=True, text=True,
                )


def test_list_kms_keys_pkcs11_registered_only_drift(
    kms, fake_db, softhsm_token, softhsm_rsa_key, softhsm_pkcs11_tool, monkeypatch,
):
    """If a KeyStorage row's ``hsm_token_id`` is not found on the token
    (drift), the row surfaces with ``state="registered_only"``. Detected
    on every list call — no separate verify pass per CR-0001 decision 2."""
    import subprocess
    from web.services import api_adapters as A
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    pki_stub = _StubPki(fake_db, kms=kms)
    monkeypatch.setattr(A, "pki", pki_stub)

    provider_id = fake_db.add_provider({
        "label": "softhsm-drift",
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
    pki_stub.get_kms().import_pkcs11_key(provider_id, hex_id, label="will-drift")

    # Delete the on-token objects out-of-band; the KeyStorage row remains.
    for obj_type in ("privkey", "pubkey"):
        subprocess.run(
            [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
             "--login", "--pin", pin,
             "--delete-object", "--type", obj_type, "--id", hex_id],
            capture_output=True, text=True,
        )

    out = A.list_kms_keys(provider_id=provider_id)
    assert out["token_enumeration"]["available"] is True
    by_token = {k["hsm_token_id"]: k for k in out["keys"] if k.get("hsm_token_id")}
    assert hex_id in by_token
    assert by_token[hex_id]["state"] == "registered_only"
    # The row keeps its KeyStorage id; deletion still goes through the
    # normal API.
    assert by_token[hex_id]["id"] is not None
