"""
Phase 4 — secret-handling story.

Covers:
- ``db:encrypted`` resolver: PIN encrypted under the master KEK on the
  provider row, decrypted at activation time.
- ``operator:prompt`` resolver: PIN supplied at activation via the KMS
  API, never stored. Sign+verify works after activation; signing fails
  cleanly before activation.
- ``validate_provider_auth_config`` rejects every illegal combination of
  ``auto_activate`` × ``auth_secret_ref`` × ``auth_secret_blob``.
- ``activate_auto_providers`` activates the seeded software-default
  provider and reports failure for missing PINs without raising.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from pypki.db import PKIDataBase
from pypki.key_encryption import (
    KEKUnavailable,
    decrypt_provider_pin,
    derive_kek,
    encrypt_pem,
    encrypt_provider_pin,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def _add_encrypted_software_key(fake_db, provider_id, pin_bytes, priv, key_type):
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    kek = derive_kek(pin_bytes, provider_id)
    blob = encrypt_pem(pem, kek)
    return fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "Encrypted",
        "private_key": blob,
        "public_key": priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "key_type": key_type,
    })


# ── db:encrypted resolver ─────────────────────────────────────────────────────

def test_db_encrypted_resolver_round_trip(kms, fake_db, hsm_pin_kek):
    """Provider PIN encrypted on the row → resolver decrypts → KEK derives →
    software key signs and verifies. End-to-end against the master KEK."""
    pin_bytes = b"per-provider-pin-different-from-master"
    blob = encrypt_provider_pin(pin_bytes)
    # Sanity: blob round-trips through the master KEK on its own.
    assert decrypt_provider_pin(blob) == pin_bytes

    provider_id = fake_db.add_provider({
        "label": "software-db-encrypted",
        "kind": "software",
        "module_path": None,
        "slot_label": None,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "db:encrypted",
        "auth_secret_blob": blob,
        "extra_json": "{}",
        "is_default": False,
    })

    priv = ec.generate_private_key(ec.SECP256R1())
    key_id = _add_encrypted_software_key(
        fake_db, provider_id, pin_bytes, priv, "ECDSA-P-256",
    )
    digest = _sha256(b"hello db-encrypted")
    sig = kms.sign_digest(key_id, digest)
    priv.public_key().verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def test_db_encrypted_missing_master_kek_fails_clearly(monkeypatch, fake_db):
    """If HSM_PIN_KEK is unset, db:encrypted resolution raises
    KEKUnavailable with an actionable message."""
    monkeypatch.delenv("HSM_PIN_KEK", raising=False)
    record = {
        "id": 1,
        "label": "p1",
        "auth_secret_ref": "db:encrypted",
        "auth_secret_blob": b"\x00" * 64,  # any non-empty blob
    }
    from pypki.key_encryption import resolve_provider_secret
    with pytest.raises(KEKUnavailable) as exc:
        resolve_provider_secret(record)
    assert "HSM_PIN_KEK" in str(exc.value)


def test_db_encrypted_wrong_master_kek_is_rejected(monkeypatch, fake_db):
    """A blob produced under one master KEK cannot be decrypted under a
    different one — the GCM tag mismatch is surfaced as KEKUnavailable
    (clean error, not a low-level InvalidTag leak)."""
    monkeypatch.setenv("HSM_PIN_KEK", "kek-A")
    blob = encrypt_provider_pin(b"some-pin")
    monkeypatch.setenv("HSM_PIN_KEK", "kek-B")  # rotated → cannot decrypt
    record = {
        "id": 1,
        "label": "p-rotated",
        "auth_secret_ref": "db:encrypted",
        "auth_secret_blob": blob,
    }
    from pypki.key_encryption import resolve_provider_secret
    with pytest.raises(KEKUnavailable) as exc:
        resolve_provider_secret(record)
    assert "different HSM_PIN_KEK" in str(exc.value)


# ── operator:prompt resolver ──────────────────────────────────────────────────

def test_operator_prompt_requires_runtime_pin(kms, fake_db, hsm_pin_kek):
    """Operator-prompt providers: signing fails before activation; succeeds
    after `kms.activate_provider(id, pin=...)` with the matching PIN."""
    pin_text = "operator-supplied-pin-1234"
    pin_bytes = pin_text.encode("utf-8")

    provider_id = fake_db.add_provider({
        "label": "software-operator-prompt",
        "kind": "software",
        "module_path": None,
        "slot_label": None,
        "auth_kind": "pin",
        "auto_activate": False,
        "auth_secret_ref": "operator:prompt",
        "auth_secret_blob": None,
        "extra_json": "{}",
        "is_default": False,
    })

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = _add_encrypted_software_key(
        fake_db, provider_id, pin_bytes, priv, "RSA-2048",
    )

    # Pre-activation: sign attempt fails with the lifecycle error, not a
    # cryptography-level surprise.
    with pytest.raises(RuntimeError) as exc:
        kms.sign_digest(key_id, _sha256(b"too soon"))
    assert "operator" in str(exc.value).lower() or "operator:prompt" in str(exc.value)

    # Activate with the right PIN, sign, verify.
    kms.activate_provider(provider_id, pin=pin_text)
    digest = _sha256(b"hello operator")
    sig = kms.sign_digest(key_id, digest)
    priv.public_key().verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))


def test_operator_prompt_pin_required(kms, fake_db, hsm_pin_kek):
    provider_id = fake_db.add_provider({
        "label": "software-needs-pin",
        "kind": "software",
        "auto_activate": False,
        "auth_secret_ref": "operator:prompt",
        "extra_json": "{}",
    })
    with pytest.raises(ValueError, match="requires a PIN"):
        kms.activate_provider(provider_id)


def test_pin_supplied_for_non_operator_provider_is_rejected(
    kms, fake_db, hsm_pin_kek,
):
    """Sending a PIN to an env-resolved provider is a 400-class error, not
    a silent override. Prevents operators from accidentally re-keying
    auto-activated providers via the activate endpoint."""
    provider_id = fake_db.add_provider({
        "label": "software-env-resolved",
        "kind": "software",
        "auto_activate": True,
        "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}",
    })
    with pytest.raises(ValueError, match="resolves its PIN automatically"):
        kms.activate_provider(provider_id, pin="ignored")


# ── auto_activate × auth_secret_ref consistency ──────────────────────────────

def test_validate_auto_activate_with_operator_prompt_rejected():
    with pytest.raises(ValueError, match="incompatible"):
        PKIDataBase.validate_provider_auth_config({
            "label": "bad", "auto_activate": True,
            "auth_secret_ref": "operator:prompt",
        })


def test_validate_manual_with_env_rejected():
    with pytest.raises(ValueError, match="auto_activate=FALSE requires"):
        PKIDataBase.validate_provider_auth_config({
            "label": "bad", "auto_activate": False,
            "auth_secret_ref": "env:FOO",
        })


def test_validate_db_encrypted_requires_blob():
    with pytest.raises(ValueError, match="auth_secret_blob"):
        PKIDataBase.validate_provider_auth_config({
            "label": "bad", "auto_activate": True,
            "auth_secret_ref": "db:encrypted",
            "auth_secret_blob": None,
        })


def test_validate_blob_only_valid_with_db_encrypted():
    with pytest.raises(ValueError, match="only valid for"):
        PKIDataBase.validate_provider_auth_config({
            "label": "bad", "auto_activate": True,
            "auth_secret_ref": "env:FOO",
            "auth_secret_blob": b"\x00" * 64,
        })


def test_validate_unknown_scheme_rejected():
    with pytest.raises(ValueError, match="must be one of"):
        PKIDataBase.validate_provider_auth_config({
            "label": "bad", "auto_activate": True,
            "auth_secret_ref": "junk:xyz",
        })


def test_validate_accepts_valid_configs():
    # Auto-activate + env
    PKIDataBase.validate_provider_auth_config({
        "label": "ok-env", "auto_activate": True,
        "auth_secret_ref": "env:HSM_PIN_KEK",
    })
    # Auto-activate + db:encrypted
    PKIDataBase.validate_provider_auth_config({
        "label": "ok-db", "auto_activate": True,
        "auth_secret_ref": "db:encrypted", "auth_secret_blob": b"\x00" * 32,
    })
    # Manual + operator:prompt
    PKIDataBase.validate_provider_auth_config({
        "label": "ok-op", "auto_activate": False,
        "auth_secret_ref": "operator:prompt",
    })


# ── activate_auto_providers ────────────────────────────────────────────────────

def test_activate_auto_providers_skips_manual(kms, fake_db, hsm_pin_kek):
    auto_id = fake_db.add_provider({
        "label": "auto", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}",
    })
    manual_id = fake_db.add_provider({
        "label": "manual", "kind": "software",
        "auto_activate": False, "auth_secret_ref": "operator:prompt",
        "extra_json": "{}",
    })

    summary = kms.activate_auto_providers()
    assert summary == {"activated": 1, "skipped": 1, "errors": 0}

    auto_status = kms.get_provider_status(auto_id)
    manual_status = kms.get_provider_status(manual_id)
    assert auto_status["state"] == "active"
    assert manual_status["state"] == "inactive"


def test_activate_auto_providers_does_not_raise_on_missing_env(
    monkeypatch, kms, fake_db,
):
    """A misconfigured auto-activate provider must NOT prevent app startup
    — it gets logged and counted as an error, other providers continue.
    Regression for kms-specs.md §6 ('failure is logged loudly but does
    not block app startup')."""
    monkeypatch.delenv("HSM_PIN_KEK", raising=False)
    monkeypatch.setenv("OK_PIN", "fine")

    fake_db.add_provider({
        "label": "broken", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:DOES_NOT_EXIST",
        "extra_json": "{}",
    })
    fake_db.add_provider({
        "label": "ok", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:OK_PIN",
        "extra_json": "{}",
    })

    summary = kms.activate_auto_providers()
    assert summary["errors"] == 1
    assert summary["activated"] == 1
