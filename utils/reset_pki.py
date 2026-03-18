import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki import PyPKI

start_time = time.time()  # Record start time

print("Reset PKI Database")

_DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
config_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_CONFIG

pki = PyPKI(config_path)

pki.reset_pki()

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
