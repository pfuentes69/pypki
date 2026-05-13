"""
Shared pytest fixtures.

Tests use a small in-memory fake of the `PKIDataBase` surface that
`KeyManagementService` actually touches (``connection``, ``get_key_record``,
``get_provider_by_id``). This keeps the unit tests fast and independent of
a running MariaDB while still exercising the real KMS dispatch path and
the real backends.

A separate fixture (``softhsm_token``) probes for SoftHSM2 and skips tests
that need a live PKCS#11 token when it is not available.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so `import pypki` works when pytest
# is invoked from anywhere under the repo.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# ── Tiny fake DB ──────────────────────────────────────────────────────────────

class FakeDB:
    """
    Minimal in-memory stand-in for ``PKIDataBase`` exposing only what the
    KMS reaches for: ``connection()`` (no-op context manager),
    ``get_key_record(key_id)``, ``get_provider_by_id(provider_id)``.
    """

    def __init__(self):
        self.providers: dict[int, dict] = {}
        self.keys: dict[int, dict] = {}

    @contextlib.contextmanager
    def connection(self):
        yield self

    def get_provider_by_id(self, provider_id: int):
        return self.providers.get(provider_id)

    def get_key_record(self, key_id: int):
        return self.keys.get(key_id)

    def list_providers(self):
        return [self.providers[i] for i in sorted(self.providers.keys())]

    # Phase 5a additions — full CRUD shim mirroring PKIDataBase.

    def insert_key(self, private_key=None, storage_type="Plain",
                   public_key=None, key_type=None,
                   hsm_slot=None, hsm_token_id=None, token_password=None,
                   provider_id=None, label=None, key_owned=True):
        # Mirror PKIDataBase.insert_key: when provider_id isn't supplied,
        # default to the row marked is_default so every new key gets a
        # provider in production-shape tests.
        if provider_id is None:
            provider_id = self.get_default_provider_id()
        record = {
            "private_key": private_key,
            "storage_type": storage_type,
            "public_key": public_key,
            "key_type": key_type,
            "hsm_slot": hsm_slot,
            "hsm_token_id": hsm_token_id,
            "token_password": token_password,
            "provider_id": provider_id,
            "label": label,
            "key_owned": bool(key_owned),
        }
        return self.add_key(record)

    def list_keys(self, provider_id=None, key_type=None):
        rows = []
        for kid in sorted(self.keys.keys()):
            row = dict(self.keys[kid])
            row["id"] = kid
            if provider_id is not None and row.get("provider_id") != provider_id:
                continue
            if key_type and row.get("key_type") != key_type:
                continue
            rows.append(row)
        return rows

    def count_key_usage(self, key_id: int):
        # Tests inject usage by setting `_usage_overrides[key_id]`. Default: 0.
        override = getattr(self, "_usage_overrides", {}).get(key_id)
        if override is not None:
            override = dict(override)
            override["total"] = sum(
                v for k, v in override.items() if k != "total"
            )
            return override
        return {"cas": 0, "ocsp_responders": 0, "certificates": 0, "total": 0}

    def get_key_usage_items(self, key_id: int):
        """In-memory mirror of ``PKIDataBase.get_key_usage_items`` used by
        ``api_adapters.get_kms_key``. Tests inject named dependents by
        setting ``_usage_items[key_id] = [{...}, ...]``."""
        override = getattr(self, "_usage_items", {}).get(key_id)
        items = list(override) if override else []
        return {"count": len(items), "items": items}

    def delete_key(self, key_id: int):
        usage = self.count_key_usage(key_id)
        if usage.get("total", 0) > 0:
            return {"deleted": False, "reason": "in_use", "usage": usage}
        if key_id not in self.keys:
            return None
        del self.keys[key_id]
        return {"deleted": True}

    def update_provider(self, provider_id: int, fields: dict) -> bool:
        if provider_id not in self.providers:
            return False
        if not fields:
            return False
        self.providers[provider_id].update(fields)
        return True

    def count_provider_keys(self, provider_id: int) -> int:
        return sum(
            1 for r in self.keys.values()
            if r.get("provider_id") == provider_id
        )

    def delete_provider(self, provider_id: int):
        prov = self.providers.get(provider_id)
        if not prov:
            return None
        if prov.get("is_default"):
            return {"deleted": False, "reason": "is_default"}
        n = self.count_provider_keys(provider_id)
        if n > 0:
            return {"deleted": False, "reason": "has_keys", "key_count": n}
        del self.providers[provider_id]
        return {"deleted": True}

    def insert_provider(self, label, kind, auth_secret_ref,
                        module_path=None, slot_label=None, auth_kind="pin",
                        auto_activate=False, auth_secret_blob=None,
                        extra_json="{}", description=None, is_default=False):
        return self.add_provider({
            "label": label, "kind": kind, "module_path": module_path,
            "slot_label": slot_label, "auth_kind": auth_kind,
            "auto_activate": auto_activate, "auth_secret_ref": auth_secret_ref,
            "auth_secret_blob": auth_secret_blob, "extra_json": extra_json,
            "description": description, "is_default": is_default,
        })

    def get_default_provider_id(self):
        for pid, prov in self.providers.items():
            if prov.get("is_default"):
                return pid
        return None

    def write_audit_log(self, resource_type, resource_id, action, user_id=0):
        """No-op shim: tests that care about audit events monkeypatch
        ``api_adapters.write_audit_log`` directly to capture them."""
        return

    def add_provider(self, record: dict) -> int:
        record = dict(record)
        record.setdefault("id", max(self.providers.keys(), default=0) + 1)
        self.providers[record["id"]] = record
        return record["id"]

    def add_key(self, record: dict) -> int:
        record = dict(record)
        record.setdefault("id", max(self.keys.keys(), default=0) + 1)
        self.keys[record["id"]] = record
        return record["id"]


@pytest.fixture
def fake_db():
    return FakeDB()


# ── KMS fixture (with shutdown teardown) ──────────────────────────────────────

@pytest.fixture
def kms(fake_db):
    """
    Yield a fresh ``KeyManagementService`` bound to the per-test ``fake_db``,
    and call ``kms.shutdown()`` on teardown so PKCS#11 sessions are released
    between tests. Without this, a leaked session leaves the SoftHSM token
    in a "user already logged in" state and the next test fails on
    ``C_Login`` with ``CKR_USER_ALREADY_LOGGED_IN``.
    """
    from pypki.kms import KeyManagementService
    instance = KeyManagementService(fake_db)
    try:
        yield instance
    finally:
        try:
            instance.shutdown()
        except Exception:
            # Best-effort; don't mask the test's primary failure.
            pass


# ── KEK / env helpers ─────────────────────────────────────────────────────────

@pytest.fixture
def hsm_pin_kek(monkeypatch):
    """Set HSM_PIN_KEK to a deterministic test value for the duration of the test."""
    monkeypatch.setenv("HSM_PIN_KEK", "pytest-kek-do-not-reuse-in-prod")
    return "pytest-kek-do-not-reuse-in-prod"


# ── SoftHSM2 token fixture ────────────────────────────────────────────────────

# Where SoftHSM2 typically lives on each platform we care about.
_SOFTHSM_MODULE_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",                  # Debian / Ubuntu / Docker image
    "/usr/lib64/pkcs11/libsofthsm2.so",                 # RHEL / Rocky / Alma
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",         # macOS Apple Silicon (Homebrew)
    "/usr/local/lib/softhsm/libsofthsm2.so",            # macOS Intel (Homebrew)
]


def _resolve_softhsm_module() -> str | None:
    for path in _SOFTHSM_MODULE_CANDIDATES:
        if os.path.exists(path):
            return path
    return os.environ.get("PKCS11_MODULE") or None


@pytest.fixture(scope="session")
def softhsm_module() -> str:
    """Skip the test if SoftHSM2 is not installed; otherwise return its module path."""
    path = _resolve_softhsm_module()
    if not path or not os.path.exists(path):
        pytest.skip("SoftHSM2 PKCS#11 module not found on this host")
    return path


@pytest.fixture(scope="session")
def softhsm_pkcs11_tool() -> str:
    """Skip if pkcs11-tool is not on PATH; otherwise return its path."""
    p = shutil.which("pkcs11-tool")
    if not p:
        pytest.skip("opensc 'pkcs11-tool' not available on PATH")
    return p


@pytest.fixture
def softhsm_rsa_key(softhsm_token, softhsm_pkcs11_tool, tmp_path):
    """Generate a fresh RSA-2048 keypair on the SoftHSM token via
    ``pkcs11-tool``. Yields ``(hex_id, pubkey_der)``. Cleans up both
    objects on teardown.

    Lives in conftest so test files outside test_kms_pkcs11_backend.py
    (e.g. the Phase 5 import test) can pick it up.
    """
    import secrets
    import subprocess
    module, token_label, pin = softhsm_token
    hex_id = secrets.token_hex(4)
    label = f"pypki-test-rsa-{hex_id}"

    subprocess.run(
        [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
         "--login", "--pin", pin,
         "--keypairgen", "--key-type", "rsa:2048",
         "--label", label, "--id", hex_id],
        check=True, capture_output=True, text=True,
    )
    try:
        der_path = tmp_path / "pub.der"
        subprocess.run(
            [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
             "--read-object", "--type", "pubkey", "--id", hex_id,
             "--output-file", str(der_path)],
            check=True, capture_output=True, text=True,
        )
        yield hex_id, der_path.read_bytes()
    finally:
        for obj_type in ("privkey", "pubkey"):
            subprocess.run(
                [softhsm_pkcs11_tool, "--module", module, "--token-label", token_label,
                 "--login", "--pin", pin,
                 "--delete-object", "--type", obj_type, "--id", hex_id],
                capture_output=True, text=True,
            )


@pytest.fixture(scope="session")
def softhsm_token(softhsm_module, softhsm_pkcs11_tool):
    """
    Locate (or skip if absent) an initialised SoftHSM2 token labelled
    ``pypki-test`` (preferred) or ``pypki-dev`` (the dev container default).
    Returns ``(module_path, token_label, user_pin)``.

    Tests that need to mutate the token (generate keys, etc.) should treat
    the token as a shared fixture — clean up after themselves.
    """
    candidates = ["pypki-test", "pypki-dev"]
    pin = os.environ.get("PKCS11_PIN", "1234")

    # Probe with pkcs11-tool to find which label exists.
    try:
        out = subprocess.run(
            [softhsm_pkcs11_tool, "--module", softhsm_module, "--list-token-slots"],
            capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        pytest.skip(f"pkcs11-tool --list-token-slots failed: {e.stderr or e}")

    for label in candidates:
        if label in out:
            return softhsm_module, label, pin

    pytest.skip(
        f"No SoftHSM2 token labelled {candidates!r} found. "
        f"Initialise one with: softhsm2-util --init-token --free "
        f"--label pypki-test --pin {pin} --so-pin 5678"
    )
