#!/bin/bash
# Make sure Python 3.12 is installed
python3 --version

# Create virtual environment
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate

# Upgrade pip and install requirements
pip install --upgrade pip
pip install -r requirements.txt

echo "Virtual environment setup complete."
echo "Activate it with: source venv/bin/activate"

