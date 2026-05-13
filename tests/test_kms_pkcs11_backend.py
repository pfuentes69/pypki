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


# ── CR-0001 §18.1: PKCS11Backend.list_keys() on-token enumeration ─────────────

def test_pkcs11_backend_list_keys_enumerates_token_objects(
    fake_db, softhsm_token, softhsm_rsa_key, softhsm_ecdsa_key, monkeypatch,
):
    """``PKCS11Backend.list_keys()`` returns one row per ``CKO_PRIVATE_KEY``
    on the open session, including keys that were never imported through
    pyPKI. The RSA and ECDSA fixtures generate their keys out-of-band via
    ``pkcs11-tool`` — neither has a ``KeyStorage`` row — so both must come
    back from the sweep with full algorithm + public-key metadata and a
    ``null`` ``unimportable_reason``. Closes step 1 of CR-0001's action
    plan (kms-specs.md §18.1)."""
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-list-keys",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    provider = fake_db.get_provider_by_id(provider_id)

    from pypki.backends.pkcs11 import PKCS11Backend
    backend = PKCS11Backend()
    backend.open(provider)
    try:
        keys = backend.list_keys()
    finally:
        backend.close()

    rsa_hex, _ = softhsm_rsa_key
    ecdsa_hex, _ = softhsm_ecdsa_key
    by_id = {k["hsm_token_id"]: k for k in keys}
    assert rsa_hex in by_id, (
        f"RSA key with CKA_ID={rsa_hex} not enumerated; got {list(by_id)}"
    )
    assert ecdsa_hex in by_id, (
        f"ECDSA key with CKA_ID={ecdsa_hex} not enumerated; got {list(by_id)}"
    )

    rsa_entry = by_id[rsa_hex]
    assert rsa_entry["key_type"] == "RSA-2048"
    assert rsa_entry["unimportable_reason"] is None
    assert rsa_entry["public_key"] is not None
    assert rsa_entry["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    assert rsa_entry["cka_label"] == f"pypki-test-rsa-{rsa_hex}"

    ecdsa_entry = by_id[ecdsa_hex]
    assert ecdsa_entry["key_type"] == "ECDSA-P-256"
    assert ecdsa_entry["unimportable_reason"] is None
    assert ecdsa_entry["public_key"] is not None
    assert ecdsa_entry["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    assert ecdsa_entry["cka_label"] == f"pypki-test-ec-{ecdsa_hex}"


def test_pkcs11_backend_list_keys_recovers_orphaned_public_via_fallback(
    fake_db, softhsm_token, softhsm_pkcs11_tool, monkeypatch,
):
    """When the paired ``CKO_PUBLIC_KEY`` object is missing,
    ``list_keys`` falls back to reading the public components off the
    private-key handle itself (CR-0003) — either ``CKA_PUBLIC_KEY_INFO``
    (PKCS#11 v3) or, for RSA, the algorithm-specific
    ``CKA_MODULUS`` + ``CKA_PUBLIC_EXPONENT``. The row surfaces with
    ``unimportable_reason=None`` and a usable PEM so the operator can
    import it through the standard affordance.

    Replaces the prior CR-0001 behaviour (paired-object lookup only)
    documented in §2.2 / §10.2."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    hex_id = secrets.token_hex(4)
    label = f"pypki-test-fallback-{hex_id}"

    _generate_rsa_on_token(softhsm_pkcs11_tool, module, token_label, pin, label, hex_id)
    # Drop the public key so the private one is orphaned — the fallback
    # path must reconstruct the SPKI from the private-key handle.
    _delete_object(softhsm_pkcs11_tool, module, token_label, pin, hex_id, "pubkey")

    provider_id = fake_db.add_provider({
        "label": "softhsm-orphan-priv-fallback",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    provider = fake_db.get_provider_by_id(provider_id)

    from pypki.backends.pkcs11 import PKCS11Backend
    backend = PKCS11Backend()
    backend.open(provider)
    try:
        keys = backend.list_keys()
    finally:
        backend.close()
        _delete_object(softhsm_pkcs11_tool, module, token_label, pin, hex_id, "privkey")

    by_id = {k["hsm_token_id"]: k for k in keys}
    assert hex_id in by_id
    entry = by_id[hex_id]
    assert entry["unimportable_reason"] is None, (
        f"Expected the fallback to recover the public key, got reason="
        f"{entry['unimportable_reason']!r} (public_key={entry['public_key']!r})"
    )
    assert entry["key_type"] == "RSA-2048"
    assert entry["public_key"] is not None
    assert entry["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    # Reconstructed PEM must parse and carry the right modulus size.
    pubkey = load_pem_public_key(entry["public_key"].encode())
    assert pubkey.key_size == 2048


def test_pkcs11_backend_list_keys_residual_public_key_unavailable(
    fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """When *both* the paired-public-key lookup and the private-handle
    attribute fallback cannot yield a usable PEM, the row keeps
    surfacing with ``unimportable_reason="public_key_unavailable"``.

    Simulates the vendor-restricted case (Luna crypto-user role with
    public components blocked, vendor that doesn't implement
    ``CKA_PUBLIC_KEY_INFO`` and seals ``CKA_MODULUS`` on private
    handles, etc.) by forcing the reconstruction helper to raise."""
    from pypki.backends import pkcs11 as backend_module

    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    hex_id, _ = softhsm_rsa_key  # the fixture leaves the paired pub in place

    def _always_unrecoverable(*_args, **_kwargs):
        raise ValueError("simulated vendor restriction on public attributes")
    monkeypatch.setattr(
        backend_module, "_read_public_key_pem_attributes", _always_unrecoverable,
    )

    provider_id = fake_db.add_provider({
        "label": "softhsm-residual-unavailable",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    provider = fake_db.get_provider_by_id(provider_id)

    backend = backend_module.PKCS11Backend()
    backend.open(provider)
    try:
        keys = backend.list_keys()
    finally:
        backend.close()

    by_id = {k["hsm_token_id"]: k for k in keys}
    assert hex_id in by_id
    entry = by_id[hex_id]
    assert entry["unimportable_reason"] == "public_key_unavailable"
    assert entry["public_key"] is None
    # Algorithm metadata still resolves — it does not depend on the
    # public-key reconstruction.
    assert entry["key_type"] == "RSA-2048"


def test_pkcs11_backend_activation_failure_slot_missing(
    fake_db, softhsm_token, monkeypatch,
):
    """A provider whose ``slot_label`` does not match any token surfaces
    as :class:`SlotNotFound`, not the generic :class:`BackendNotActive`.
    Lets the API render a "the slot is gone — check the token / hardware"
    banner instead of conflating with operator-prompt-not-activated."""
    from pypki.backends.base import BackendNotActive, SlotNotFound
    from pypki.backends.pkcs11 import PKCS11Backend

    module, _real_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-slot-missing",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": "definitely-not-a-real-token-label",
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    provider = fake_db.get_provider_by_id(provider_id)

    backend = PKCS11Backend()
    with pytest.raises(SlotNotFound) as exc_info:
        backend.open(provider)
    # Subclass relationship preserves backwards-compat with the existing
    # ``except BackendNotActive:`` catches at every call site.
    assert isinstance(exc_info.value, BackendNotActive)


def test_pkcs11_backend_activation_failure_auth(
    fake_db, softhsm_token, monkeypatch,
):
    """Wrong PIN surfaces as :class:`AuthenticationFailed`, not the
    generic :class:`BackendNotActive`. Models the "token was
    reinitialised with a new PIN" case the operator hits when
    SoftHSM tokens are recreated out-of-band."""
    from pypki.backends.base import AuthenticationFailed, BackendNotActive
    from pypki.backends.pkcs11 import PKCS11Backend

    module, token_label, _real_pin = softhsm_token
    # Set the resolver's env var to a wrong PIN; the helper expects a
    # non-empty string so we use something the token will definitely
    # reject.
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", "wrong-pin-9999")
    provider_id = fake_db.add_provider({
        "label": "softhsm-bad-pin",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    provider = fake_db.get_provider_by_id(provider_id)

    backend = PKCS11Backend()
    with pytest.raises(AuthenticationFailed) as exc_info:
        backend.open(provider)
    assert isinstance(exc_info.value, BackendNotActive)


def test_pkcs11_backend_activation_failure_module_load(
    fake_db, softhsm_token, monkeypatch,
):
    """Pointing at a non-existent shared library surfaces as
    :class:`ModuleLoadFailed` so the UI directs the operator at the
    deployment config rather than the token state."""
    from pypki.backends.base import BackendNotActive, ModuleLoadFailed
    from pypki.backends.pkcs11 import PKCS11Backend

    _module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-bad-module",
        "kind": "pkcs11",
        "module_path": "/nonexistent/path/to/softhsm2.so",
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    provider = fake_db.get_provider_by_id(provider_id)

    backend = PKCS11Backend()
    with pytest.raises(ModuleLoadFailed) as exc_info:
        backend.open(provider)
    assert isinstance(exc_info.value, BackendNotActive)


def test_pkcs11_backend_sign_digest_classifies_midsession_slot_loss(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """CR-0004 decision 1 + 3: when ``sign_digest``'s one-shot reconnect
    itself fails because the slot is gone, the typed
    :class:`SlotNotFound` propagates from the backend, and the KMS
    evicts the cached backend so the next call re-runs activation
    cleanly.

    Staged via mocks rather than a real ``softhsm2-util --delete-token``
    (which would destroy the shared dev token) — the mock returns
    ``CKR_TOKEN_NOT_PRESENT`` first on the in-flight sign and then on
    the reconnect attempt."""
    import PyKCS11
    from pypki.backends.base import SlotNotFound

    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-midsession-loss",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })

    # Register the fixture-created token key and load it normally so the
    # cached backend + handle are in the legitimate "active" state.
    hex_id, _ = softhsm_rsa_key
    imported = kms.import_pkcs11_key(provider_id, hex_id, label="midsession")
    key_id = imported["key_id"]
    kms.load_key(key_id)
    assert provider_id in kms._KeyManagementService__backends
    backend = kms._KeyManagementService__backends[provider_id]

    # Patch the backend so the next sign call (and the reconnect's
    # session-open) both fail with CKR_TOKEN_NOT_PRESENT — simulating
    # the slot disappearing mid-session.
    token_missing = PyKCS11.PyKCS11Error(int(PyKCS11.CKR_TOKEN_NOT_PRESENT))
    def _sign_dead(*_a, **_kw):
        raise token_missing
    monkeypatch.setattr(backend, "_sign_with_state", _sign_dead)
    def _reopen_dead(*_a, **_kw):
        raise token_missing
    monkeypatch.setattr(backend._helper, "open_session", _reopen_dead)

    digest = _sha256(b"midsession-loss")
    with pytest.raises(SlotNotFound):
        kms.sign_digest(key_id, digest)

    # The KMS evicted the broken cached backend (decision 3).
    assert provider_id not in kms._KeyManagementService__backends
    # Handle cache for the same provider was cleared too — the next
    # signing attempt will go through load_key, which re-runs activation.
    assert key_id not in kms._KeyManagementService__handle_cache


def test_pkcs11_backend_list_keys_classifies_midsession_failure(
    kms, fake_db, softhsm_token, softhsm_rsa_key, monkeypatch,
):
    """CR-0004 decision 2: ``list_keys`` does not retry — a mid-session
    ``PyKCS11Error`` is classified and re-raised. ``probe_key_on_token``
    / ``list_kms_keys`` map the typed exception to the right
    ``token_enumeration.reason`` (covered separately) so the operator
    sees specific guidance instead of a generic backend-error envelope."""
    import PyKCS11
    from pypki.backends.base import SlotNotFound

    module, token_label, pin = softhsm_token
    monkeypatch.setenv("PYPKI_TEST_SOFTHSM_PIN", pin)
    provider_id = fake_db.add_provider({
        "label": "softhsm-midsession-list",
        "kind": "pkcs11",
        "module_path": module,
        "slot_label": token_label,
        "auth_kind": "pin",
        "auto_activate": True,
        "auth_secret_ref": "env:PYPKI_TEST_SOFTHSM_PIN",
        "extra_json": "{}",
        "is_default": False,
    })
    # Activate by listing once with the real session.
    kms.list_provider_token_keys(provider_id)
    backend = kms._KeyManagementService__backends[provider_id]

    # Patch the live session's findObjects to raise the typed PKCS#11
    # "token not present" so the wrapper reclassifies as SlotNotFound.
    session = backend._helper.get_session()
    def _dead_find(*_a, **_kw):
        raise PyKCS11.PyKCS11Error(int(PyKCS11.CKR_TOKEN_NOT_PRESENT))
    monkeypatch.setattr(session, "findObjects", _dead_find)

    with pytest.raises(SlotNotFound):
        kms.list_provider_token_keys(provider_id)
    # And the wrapper at the KMS level evicted the cached backend.
    assert provider_id not in kms._KeyManagementService__backends


def test_software_backend_list_keys_returns_empty():
    """``SoftwareBackend.list_keys()`` returns ``[]`` — software keys live
    exclusively in ``KeyStorage``, the backend has no parallel store to
    enumerate. The merged-listing adapter (kms-specs.md §18.1) relies on
    this so it can call ``list_keys`` uniformly on either backend kind."""
    from pypki.backends.software import SoftwareBackend
    backend = SoftwareBackend()
    assert backend.list_keys() == []
