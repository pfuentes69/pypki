"""
Regression tests for the end-entity key-escrow regime alignment.

Background: pre-fix, ``generate_pkcs12(store_key=True, passphrase)`` wrote
a row with ``storage_type='Encrypted'`` whose ``private_key`` column held
a *passphrase-encrypted* PEM, colliding with the Phase 0.2 meaning of
``'Encrypted'`` (KEK-wrapped ciphertext). The fix introduces a distinct
``'PassphraseEncrypted'`` storage type and uniformly KEK-wraps both
regimes (defense in depth).

These tests cover:
- ``_looks_like_pem`` accepts unencrypted PEM and rejects passphrase-
  encrypted PEM, so the legacy-detection path doesn't double-encrypt
  passphrase-PEM rows.
- ``SoftwareBackend.load_key`` refuses ``PassphraseEncrypted`` rows with
  a clear pointer to the re-download flow rather than a generic crypto
  error.
- A KEK-wrapped passphrase-PEM blob round-trips: decrypt under the KEK
  yields the passphrase-PEM, and ``load_pem_private_key`` with the
  passphrase yields the original key.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pypki.backends.software import _looks_like_pem
from pypki.key_encryption import decrypt_pem, derive_kek, encrypt_pem


# ── _looks_like_pem refinement ──────────────────────────────────────────────

def test_looks_like_pem_accepts_unencrypted_pkcs8():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg…\n"
        "-----END PRIVATE KEY-----\n"
    )
    assert _looks_like_pem(pem) is True


def test_looks_like_pem_accepts_unencrypted_pkcs1():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA…\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    assert _looks_like_pem(pem) is True


def test_looks_like_pem_rejects_pkcs8_encrypted():
    """The PKCS#8 encrypted marker — the regime collision case. Must NOT
    match, so the migration's "Encrypted is actually plaintext PEM"
    fallback skips passphrase-PEM rows instead of double-encrypting them."""
    pem = (
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "MIIE6TAbBgkqhkiG9w0BBQMwDgQI…\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    assert _looks_like_pem(pem) is False


def test_looks_like_pem_rejects_pkcs1_proc_type_encrypted():
    """Legacy PKCS#1 / SEC1 form for password-protected PEM uses an
    explicit ``Proc-Type: 4,ENCRYPTED`` header line."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,…\n\n"
        "Mg+oU93ZNQ4HX…\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    assert _looks_like_pem(pem) is False


def test_looks_like_pem_rejects_non_pem_bytes():
    assert _looks_like_pem(b"") is False
    assert _looks_like_pem(b"random bytes") is False
    assert _looks_like_pem(None) is False
    assert _looks_like_pem(b"+aGVsbG8=") is False  # base64-ish ciphertext


# ── SoftwareBackend.load_key refusal for PassphraseEncrypted ────────────────

def test_software_backend_refuses_passphrase_encrypted(kms, fake_db, hsm_pin_kek):
    """A PassphraseEncrypted row triggers a clear ValueError pointing at
    the re-download flow, not a low-level cryptography error."""
    pid = fake_db.add_provider({
        "label": "software-default", "kind": "software",
        "auto_activate": True, "auth_secret_ref": "env:HSM_PIN_KEK",
        "extra_json": "{}", "is_default": True,
    })

    # Build a realistic-shape blob: passphrase-encrypted PEM, KEK-wrapped.
    priv = ec.generate_private_key(ec.SECP256R1())
    passphrase = b"super-secret-pkcs12-pass"
    inner_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), pid)
    blob = encrypt_pem(inner_pem, kek)

    key_id = fake_db.add_key({
        "provider_id": pid,
        "storage_type": "PassphraseEncrypted",
        "private_key": blob,
        "key_type": "ECDSA-P-256",
    })

    with pytest.raises(ValueError) as exc:
        kms.sign_digest(key_id, b"\x00" * 32)
    msg = str(exc.value)
    assert "PassphraseEncrypted" in msg
    assert "build_pkcs12_for_certificate" in msg


# ── Round-trip of the double-wrap regime ─────────────────────────────────────

def test_double_wrap_round_trip(hsm_pin_kek):
    """Passphrase-PEM, KEK-wrapped under a per-provider KEK, can be
    unwrapped (with the KEK) and re-loaded with the original passphrase.
    This is the contract ``build_pkcs12_for_certificate`` relies on."""
    priv = ec.generate_private_key(ec.SECP256R1())
    passphrase = b"operator-pkcs12-passphrase"

    inner_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )

    provider_id = 7
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), provider_id)

    # Encrypt under KEK …
    blob = encrypt_pem(inner_pem, kek)
    # … then unwrap and re-load with the passphrase.
    recovered_pem = decrypt_pem(blob, kek)
    assert recovered_pem == inner_pem  # KEK round-trip is exact

    loaded = load_pem_private_key(recovered_pem, password=passphrase)
    # Public-key bytes match the original — proves the key survived both wraps.
    assert (
        loaded.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        == priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_double_wrap_wrong_passphrase_fails_clearly(hsm_pin_kek):
    """Wrong passphrase fails at ``load_pem_private_key`` after a successful
    KEK unwrap — so the operator gets a passphrase-specific error, not a
    KEK-specific one."""
    priv = ec.generate_private_key(ec.SECP256R1())
    inner_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"correct-pass"),
    )
    kek = derive_kek(hsm_pin_kek.encode("utf-8"), 7)
    blob = encrypt_pem(inner_pem, kek)

    recovered_pem = decrypt_pem(blob, kek)
    with pytest.raises(Exception):  # cryptography raises a specific error
        load_pem_private_key(recovered_pem, password=b"wrong-pass")
