"""
KMS dispatch through SoftwareBackend — sign + verify for RSA and ECDSA.

Exercises the full ``KeyManagementService.sign_digest`` path:
KMS → CryptoProviders row lookup → SoftwareBackend.open() (resolves
HSM_PIN_KEK, derives KEK) → SoftwareBackend.load_key() (decrypts
encrypted-at-rest blob) → SoftwareBackend.sign_digest() → returns bytes
that verify against the original public key.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat,
)

from pypki.key_encryption import derive_kek, encrypt_pem
from pypki.kms import KeyManagementService


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_software_provider(fake_db):
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


def _add_encrypted_software_key(fake_db, provider_id, kek, priv, key_type):
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    blob = encrypt_pem(pem, kek)
    return fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "Encrypted",
        "private_key": blob,
        "public_key": priv.public_key().public_bytes(
            Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "key_type": key_type,
    })


def _sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_kms_signs_rsa_through_software_backend(kms, fake_db, hsm_pin_kek):
    """RSA-2048 key encrypted-at-rest, decrypted on activate, signed via KMS."""
    provider_id = _make_software_provider(fake_db)
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), provider_id)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = _add_encrypted_software_key(fake_db, provider_id, kek, priv, "RSA-2048")


    msg = b"hello pypki software backend"
    digest = _sha256(msg)
    signature = kms.sign_digest(key_id, digest)

    # Verify with the original public key — proves the encrypt → decrypt →
    # sign chain produced a valid signature for the right key.
    priv.public_key().verify(
        signature, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256())
    )


def test_kms_signs_ecdsa_through_software_backend(kms, fake_db, hsm_pin_kek):
    """ECDSA P-256 key encrypted-at-rest, signed via KMS, verified."""
    provider_id = _make_software_provider(fake_db)
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), provider_id)
    priv = ec.generate_private_key(ec.SECP256R1())
    key_id = _add_encrypted_software_key(fake_db, provider_id, kek, priv, "ECDSA-P-256")


    digest = _sha256(b"hello pypki ecdsa")
    signature = kms.sign_digest(key_id, digest)

    priv.public_key().verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def test_kms_caches_handle_across_calls(kms, fake_db, hsm_pin_kek):
    """Second sign call reuses the cached handle — backend opened once."""
    provider_id = _make_software_provider(fake_db)
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), provider_id)
    priv = ec.generate_private_key(ec.SECP256R1())
    key_id = _add_encrypted_software_key(fake_db, provider_id, kek, priv, "ECDSA-P-256")


    assert not kms.is_loaded(key_id)
    kms.sign_digest(key_id, _sha256(b"first"))
    assert kms.is_loaded(key_id)
    # Second call should not re-load.
    kms.sign_digest(key_id, _sha256(b"second"))
    assert kms.is_loaded(key_id)


def test_kms_deactivate_evicts_handle(kms, fake_db, hsm_pin_kek):
    """Deactivating a provider drops its handles — next call must re-open."""
    provider_id = _make_software_provider(fake_db)
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), provider_id)
    priv = ec.generate_private_key(ec.SECP256R1())
    key_id = _add_encrypted_software_key(fake_db, provider_id, kek, priv, "ECDSA-P-256")


    kms.sign_digest(key_id, _sha256(b"once"))
    assert kms.is_loaded(key_id)

    kms.deactivate_provider(provider_id)
    assert not kms.is_loaded(key_id)

    # Sign again — backend re-opens, key reloads, signature still verifies.
    digest = _sha256(b"twice")
    signature = kms.sign_digest(key_id, digest)
    priv.public_key().verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def test_kms_unknown_key_raises(kms, fake_db, hsm_pin_kek):
    _make_software_provider(fake_db)

    with pytest.raises(KeyError):
        kms.sign_digest(99999, b"x" * 32)
