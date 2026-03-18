import logging
import os

from web import create_app

# Configure logging for the application
os.makedirs("out", exist_ok=True)
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
