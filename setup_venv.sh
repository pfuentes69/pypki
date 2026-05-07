#!/bin/bash
set -euo pipefail

# Verify Python 3.11+ is available
if ! python3 -c "import sys; assert sys.version_info >= (3, 11), f'need 3.11+, got {sys.version}'" 2>/dev/null; then
    echo "Error: Python 3.11 or newer is required." >&2
    echo "  Found:          $(python3 --version 2>&1)" >&2
    echo "  macOS:          brew install python@3.13" >&2
    echo "  Debian/Ubuntu:  sudo apt-get install python3.13 python3.13-venv" >&2
    exit 1
fi

# Warn before destroying an existing environment
if [[ -d .venv ]]; then
    echo "Note: existing .venv will be removed and recreated."
    deactivate 2>/dev/null || true
fi

rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "Virtual environment ready."
echo "Activate with: source .venv/bin/activate"
