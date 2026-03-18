import sys
import os
import glob

# Adds the project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki import PyPKI

_DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
_BACKUP_DIR     = os.path.join(os.path.dirname(__file__), '..', 'out', 'backup')

config_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_CONFIG

# ── Discover backup files ─────────────────────────────────────────────────────
bak_files = sorted(glob.glob(os.path.join(_BACKUP_DIR, '*.bak')))

if not bak_files:
    print(f"No backup files found in {_BACKUP_DIR}")
    sys.exit(1)

print("Available backups (newest last):")
for i, path in enumerate(bak_files):
    size_kb = os.path.getsize(path) / 1024
    print(f"  [{i + 1}] {os.path.basename(path)}  ({size_kb:.1f} KB)")

latest = bak_files[-1]
print(f"\nLatest backup: {os.path.basename(latest)}")

# ── Confirmation ──────────────────────────────────────────────────────────────
answer = input("\nRestore this backup? This will OVERWRITE the current database. [yes/N] ").strip().lower()
if answer != 'yes':
    print("Aborted.")
    sys.exit(0)

# ── Restore ───────────────────────────────────────────────────────────────────
print(f"\nRestoring {os.path.basename(latest)} ...")
start = time.time()

pki = PyPKI(config_path)
pki.restore_backup(latest)

elapsed = time.time() - start
print(f"Restore completed in {elapsed:.3f} seconds.")
print("\nAll done here... Bye!")
