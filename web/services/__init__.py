import sys
import os
import atexit

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.hazmat.primitives import serialization
from pypki import CertificationAuthority, PyPKI, logger


def _autoload_env_file():
    """
    Load ``KEY=VALUE`` lines from a ``.env`` at the project root into
    ``os.environ`` if they are not already set. Skipped silently when the
    file does not exist.

    Lets the local-dev path (`python web/app.py`) pick up the same
    HSM_PIN_KEK / DB_* values that the Docker entrypoint receives via
    ``docker-compose.yml``'s ``${HSM_PIN_KEK:?…}`` reference, without
    requiring operators to remember `set -a; source .env; set +a` every
    time. Tiny inline parser to avoid adding python-dotenv as a
    dependency for a five-line operation.
    """
    env_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..', '.env')
    )
    if not os.path.isfile(env_path):
        return
    loaded = []
    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                # Strip surrounding quotes commonly added by shell tools.
                value = value.strip()
                if (len(value) >= 2 and value[0] == value[-1]
                        and value[0] in ('"', "'")):
                    value = value[1:-1]
                if key and key not in os.environ:
                    os.environ[key] = value
                    loaded.append(key)
        if loaded:
            logger.info(
                f"Auto-loaded {len(loaded)} env var(s) from {env_path}: "
                f"{', '.join(loaded)}"
            )
    except Exception as e:
        logger.warning(f"Failed to auto-load .env at {env_path}: {e}")


_autoload_env_file()


CRL_PUBLICATION_FREQ = 10 * 60
CONFIG_PATH = os.environ.get("PYPKI_CONFIG", "config/config.json")

crl_task_enabled = True

pki = PyPKI(CONFIG_PATH)

pki.load_ocsp_responders()
pki.load_template_collection()
pki.load_ca_collection()

# Activate every crypto provider with auto_activate=TRUE so PKCS#11
# sessions and software KEKs are ready before the first signing request.
# Failures are logged but non-fatal (kms-strategy.md §6).
try:
    pki.get_kms().activate_auto_providers()
except Exception:
    logger.exception("KMS: activate_auto_providers raised at startup")

# Select default CA
#ca: CertificationAuthority = pki.select_ca_by_name("IoT Root CA 1")

def generate_crls():
    """
    Refresh CRLs for every loaded CA. Per-CA failures (typically: the CA's
    crypto provider is inactive because its PIN/KEK is unavailable) are
    logged but do not abort the whole pass — kms-strategy.md §6 mandates
    that a failing provider must not take the management surface down.
    """
    ca_collection = pki.get_ca_collection()
    for ca_item in ca_collection:
        try:
            crl = pki.generate_crl(ca_item["id"])
            ca_name = ca_item["name"].replace(' ', '_')
            with open(f"out/crl/{ca_name}.crl", "wb") as crl_file:
                crl_file.write(crl.public_bytes(serialization.Encoding.DER))
            with open(f"out/crl/{ca_name}.pem.crl", "wb") as crl_file:
                crl_file.write(crl.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(
                f"CRL generation failed for CA '{ca_item.get('name')}' "
                f"(id={ca_item.get('id')}): {e}"
            )

def services_task():
    logger.info("Services task")
    if crl_task_enabled:
        logger.info("Update CRLs")
        try:
            generate_crls()
        except Exception:
            logger.exception("services_task: generate_crls failed")


# Run the Services task now
services_task()

scheduler = BackgroundScheduler()
scheduler.add_job(func=services_task, trigger="interval", seconds=CRL_PUBLICATION_FREQ)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

# Close every active KMS backend (PKCS#11 sessions, software KEKs) on
# process exit — see doc/kms-strategy.md §6 (activation lifecycle).
atexit.register(lambda: pki.get_kms().shutdown())
