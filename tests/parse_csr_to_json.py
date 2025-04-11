import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json

from pypki.pki_tools import PKITools

# Example usage
if __name__ == "__main__":
    with open("request_examples/example.csr", "r") as f:
        pem_csr = f.read()

    result = PKITools.parse_csr_to_json(pem_csr)
    print(json.dumps(result, indent=4))