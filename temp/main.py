# main.py
import json
from certificates import Certificates
from certificate import Certificate

def load_config():
    """
    Load the database configuration from a JSON file.
    """
    with open("config.json", "r") as f:
        return json.load(f)

def main():
    # Load database configuration from the config file
    config = load_config()

    # Create an instance of the Certificates class
    certs = Certificates(config)

    # Path to your PEM file
    pem_file_path = "cert_sample.pem"

    # Read the PEM file
    try:
        with open(pem_file_path, 'rb') as f:
            pem_data = f.read()

        # Create a Certificate object from PEM data
        certificate = Certificate.from_pem(pem_data)

        # Print certificate details
        certificate.print_details()

        # Insert the certificate into the database
        certs.insert_certificate(certificate)

    except Exception as e:
        print(f"Error loading PEM file: {e}")

    finally:
        # Close the database connection
        certs.close_connection()

if __name__ == "__main__":
    main()
