"""
KMS dispatch through PKCS11Backend — exercises the full path against a
real SoftHSM2 token.

After Phase 1 (Gaps 1 + 2 closed), both RSA and ECDSA signatures from
the SoftHSM token verify against the public key read off the token, so
these tests now constitute the regression suite for HSM-backed signing.

The fixtures skip gracefully when SoftHSM2 / pkcs11-tool / a prepared
token are not present, so the suite stays green on machines without HSM
support installed.
"""
from __future__ import annotations

import secrets
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from pypki.kms import KeyManagementService


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def _generate_rsa_on_token(tool, module, token_label, pin, label, hex_id):
    subprocess.run(
        [tool, "--module", module, "--token-label", token_label,
         "--login", "--pin", pin,
         "--keypairgen", "--key-type", "rsa:2048",
         "--label", label, "--id", hex_id],
        check=True, capture_output=True, text=True,
    )


def _generate_ecdsa_on_token(tool, module, token_label, pin, label, hex_id, curve="secp256r1"):
    subprocess.run(
        [tool, "--module", module, "--token-label", token_label,
         "--login", "--pin", pin,
         "--keypairgen", "--key-type", f"EC:{curve}",
         "--label", label, "--id", hex_id],
        check=True, capture_output=True, text=True,
    )


def _delete_object(tool, module, token_label, pin, hex_id, type_):
    # Best-effort cleanup; ignore failures so a half-cleaned token doesn't
    # cascade into spurious test failures.
    subprocess.run(
        [tool, "--module", module, "--token-label", token_label,
         "--login", "--pin", pin,
         "--delete-object", "--type", type_, "--id", hex_id],
        capture_output=True, text=True,
    )


def _read_pubkey_pem_from_token(tool, module, token_label, hex_id, tmp_path):
    """Read the public key off the token and convert to PEM."""
    der_path = tmp_path / "pub.der"
    subprocess.run(
        [tool, "--module", module, "--token-label", token_label,
         "--read-object", "--type", "pubkey", "--id", hex_id,
         "--output-file", str(der_path)],
        check=True, capture_output=True, text=True,
    )
    return der_path.read_bytes()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def softhsm_ecdsa_key(softhsm_token, softhsm_pkcs11_tool, tmp_path):
    """Generate a fresh ECDSA P-256 keypair on the SoftHSM token. Yields
    ``(hex_id, pubkey_der)``. Cleans up both objects on teardown."""
    module, token_label, pin = softhsm_token
    hex_id = secrets.token_hex(4)
    label = f"pypki-test-ec-{hex_id}"

    _generate_ecdsa_on_token(softhsm_pkcs11_tool, module, token_label, pin, label, hex_id)
    try:
        pub_der = _read_pubkey_pem_from_token(
            softhsm_pkcs11_tool, module, token_label, hex_id, tmp_path
        )
        yield hex_id, pub_der
    finally:
        _delete_object(softhsm_pkcs11_tool, module, token_label, pin, hex_id, "privkey")
        _delete_object(softhsm_pkcs11_tool, module, token_label, pin, hex_id, "pubkey")


@pytest.fixture
def pkcs11_provider_in_db(fake_db, softhsm_token):
    module, token_label, pin = softhsm_token
    return fake_db.add_provider({
        "label": "softhsm-test",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        # Read the PIN out of an env var the test sets up via monkeypatch
        # below — see test bodies.
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    }), pin


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_kms_pkcs11_dispatch_returns_bytes(
    kms, fake_db, pkcs11_provider_in_db, softhsm_rsa_key, monkeypatch,
):
    """
    The full KMS → PKCS11Backend → KeyTools → SoftHSM2 dispatch chain
    must run without raising. We do not assert anything about the
    signature's correctness here — that lands in Phase 1 once Gap 1 is
    fixed (see ``test_kms_pkcs11_rsa_sign_verifies`` below).
    """
    provider_id, pin = pkcs11_provider_in_db
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    hex_id, _ = softhsm_rsa_key
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "key_type": "RSA-2048",
        "hsm_token_id": hex_id,        # CKA_ID, hex string per current contract
        "hsm_slot": None,              # ignored at this phase (Gap 3)
        "token_password": None,        # provider resolves the PIN
    })


    sig = kms.sign_digest(key_id, _sha256(b"hello hsm dispatch"))
    assert isinstance(sig, (bytes, bytearray))
    assert len(sig) > 0


def test_kms_pkcs11_rsa_sign_verifies(
    kms, fake_db, pkcs11_provider_in_db, softhsm_rsa_key, monkeypatch,
):
    """
    Generates an RSA key on the SoftHSM token, signs a digest through KMS,
    and verifies the signature against the public key read off the token.
    Regression for Gap 1 (RSA-on-HSM PKCS#1 v1.5 DigestInfo prefix).
    """
    provider_id, pin = pkcs11_provider_in_db
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    hex_id, pub_der = softhsm_rsa_key
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "key_type": "RSA-2048",
        "hsm_token_id": hex_id,
        "hsm_slot": None,
        "token_password": None,
    })

    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pubkey = load_der_public_key(pub_der)


    digest = _sha256(b"hello hsm rsa")
    sig = kms.sign_digest(key_id, digest)

    pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))


def test_kms_pkcs11_wrong_slot_label_is_rejected(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """
    A provider whose ``slot_label`` does not match any token on the
    configured PKCS#11 module must fail with a clear error that names
    the available labels — the slot-resolution fix for Gap 3 (numeric
    slot ids are not stable across reinitialisations).
    """
    module, real_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    bad_label = "no-such-token-xyz"
    provider_id = fake_db.add_provider({
        "label": "softhsm-wrong-label",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": bad_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    hex_id, _ = softhsm_rsa_key
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "key_type": "RSA-2048",
        "hsm_token_id": hex_id,
        "hsm_slot": None,
        "token_password": None,
    })


    with pytest.raises(RuntimeError) as exc:
        kms.sign_digest(key_id, _sha256(b"this should fail before signing"))

    msg = str(exc.value)
    assert bad_label in msg
    # The real token's label must appear in the "available" list to make
    # the error actionable for an operator typoing slot_label.
    assert real_label in msg


def test_kms_pkcs11_concurrent_signs_share_one_session(
    kms, fake_db, pkcs11_provider_in_db, softhsm_rsa_key, monkeypatch,
):
    """
    8 threads × 50 sign calls against the same RSA key on SoftHSM. Each
    signature must verify. The PKCS11Backend serialises calls on the
    shared session via its internal lock; the KMS-level double-checked
    cache lock prevents concurrent first-use from double-loading.

    Regression for Gap 6 (one session per provider, not per cached key)
    and Gap 7 (load_key not thread-safe).
    """
    import concurrent.futures

    provider_id, pin = pkcs11_provider_in_db
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    hex_id, pub_der = softhsm_rsa_key
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "key_type": "RSA-2048",
        "hsm_token_id": hex_id,
        "hsm_slot": None,
        "token_password": None,
    })

    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pubkey = load_der_public_key(pub_der)



    def _sign_one(i):
        digest = _sha256(f"concurrent-{i}".encode("ascii"))
        sig = kms.sign_digest(key_id, digest)
        pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        return True

    n_threads = 8
    n_iters = 50
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as ex:
        results = list(ex.map(_sign_one, range(n_threads * n_iters)))

    assert all(results)
    assert len(results) == n_threads * n_iters


def test_kms_shutdown_closes_active_backends(
    kms, fake_db, pkcs11_provider_in_db, softhsm_rsa_key, monkeypatch,
):
    """
    After ``kms.shutdown()`` every backend is closed and the cache is
    empty. The next sign call must re-open the backend cleanly — proves
    PKCS#11 session lifecycle is provider-scoped, not process-scoped
    (Gap 6, atexit hook).
    """
    provider_id, pin = pkcs11_provider_in_db
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    hex_id, pub_der = softhsm_rsa_key
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "key_type": "RSA-2048",
        "hsm_token_id": hex_id,
        "hsm_slot": None,
        "token_password": None,
    })


    kms.sign_digest(key_id, _sha256(b"first"))
    assert kms.is_loaded(key_id)

    kms.shutdown()
    assert not kms.is_loaded(key_id)

    # Re-sign after shutdown — backend reactivates on demand.
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pubkey = load_der_public_key(pub_der)
    digest = _sha256(b"after-shutdown")
    sig = kms.sign_digest(key_id, digest)
    pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))


def test_kms_pkcs11_ecdsa_sign_verifies(
    kms, fake_db, pkcs11_provider_in_db, softhsm_ecdsa_key, monkeypatch,
):
    """
    Generates an ECDSA P-256 key on the SoftHSM token, signs a digest
    through KMS, and verifies the signature against the public key read
    off the token. Regression for Gap 2 (ECDSA-on-HSM mechanism +
    DER-encoding of (r, s)).
    """
    provider_id, pin = pkcs11_provider_in_db
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)

    hex_id, pub_der = softhsm_ecdsa_key
    key_id = fake_db.add_key({
        "provider_id": provider_id,
        "storage_type": "HSM",
        "key_type": "ECDSA-P-256",
        "hsm_token_id": hex_id,
        "hsm_slot": None,
        "token_password": None,
    })

    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pubkey = load_der_public_key(pub_der)


    digest = _sha256(b"hello hsm ecdsa")
    sig = kms.sign_digest(key_id, digest)

    pubkey.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
