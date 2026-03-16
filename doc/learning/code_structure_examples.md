Great! Here’s a complete walkthrough with examples for each of those files to show how `your_package` is structured and used throughout the project.

---

### ✅ `your_package/__init__.py`
Expose key modules or functionality at the package level:
```python
from . import utils
from . import core
```

---

### ✅ `your_package/utils/__init__.py`
Make submodules importable as `your_package.utils.crypto_utils`, etc.:
```python
from .crypto_utils import CryptoHelper
from .validators import is_valid_input
```

---

### ✅ `your_package/utils/crypto_utils.py`
Shared cryptographic utility:
```python
import hashlib

class CryptoHelper:
    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
```

---

### ✅ `api/app.py`
Flask app that uses `your_package`:
```python
from flask import Flask
from api.routes.main_routes import register_routes
from your_package.utils.crypto_utils import CryptoHelper

def create_app():
    app = Flask(__name__)
    register_routes(app)

    # Example usage of your_package in app initialization
    print("Crypto module SHA256 test:", CryptoHelper.sha256(b"hello"))
    
    return app

app = create_app()
```

---

### ✅ `api/routes/main_routes.py`
Flask routes using shared logic from `your_package`:
```python
from flask import Blueprint, request, jsonify
from your_package.utils.crypto_utils import CryptoHelper

bp = Blueprint('main', __name__)

@bp.route('/hash', methods=['POST'])
def hash_data():
    data = request.json.get("data", "")
    hashed = CryptoHelper.sha256(data.encode())
    return jsonify({"hash": hashed})

def register_routes(app):
    app.register_blueprint(bp)
```

---

### ✅ `examples/example_1.py`
A standalone script using `your_package` directly:
```python
from your_package.utils.crypto_utils import CryptoHelper

def main():
    data = b"My example data"
    print("Hash of data:", CryptoHelper.sha256(data))

if __name__ == "__main__":
    main()
```

---

### ✅ `tests/test_utils.py`
Unit test for the utility class:
```python
import unittest
from your_package.utils.crypto_utils import CryptoHelper

class TestCryptoUtils(unittest.TestCase):
    def test_sha256(self):
        data = b"test"
        expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        self.assertEqual(CryptoHelper.sha256(data), expected)

if __name__ == "__main__":
    unittest.main()
```

---

This setup makes it very easy to reuse your core logic in **Flask APIs**, **example scripts**, and **tests** without duplication. Let me know if you want to add dependency injection, logging, or move toward packaging it for distribution!