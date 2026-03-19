import logging
import os

from web import create_app

# Ensure all required output directories exist before anything else runs
for _d in ("out", "out/crl", "out/backup"):
    os.makedirs(_d, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("out/app.log"),
        logging.StreamHandler()
    ]
)

app = create_app()

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=8080)
