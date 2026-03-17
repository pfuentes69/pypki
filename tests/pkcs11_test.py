DESCRIPTION = "PKCS#11 HSM Test"

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pypki.pkcs11_helper import PKCS11Helper

pkcs11 = PKCS11Helper()


def list_certificates():
    try:
        certs = pkcs11.get_certificates()
        print(f"Found {len(certs)} certificate(s).")
        for cert in certs:
            try:
                attrs = pkcs11.get_session().getAttributeValue(cert, [PyKCS11.CKA_LABEL], allAsBinary=False)
                label = attrs[0] if attrs and attrs[0] else "Unknown Label"
                print(f" - Certificate Label: {label}")
                id_value = pkcs11.get_session().getAttributeValue(cert, [PyKCS11.CKA_ID], allAsBinary=False)
                if id_value:
                    hex_string = ''.join(f'{byte:02X}' for byte in id_value[0])
                    print(f" - ID value: {hex_string}")
                cert_value = pkcs11.get_session().getAttributeValue(cert, [PyKCS11.CKA_VALUE], allAsBinary=False)
                if cert_value:
                    cert_der = x509.load_der_x509_certificate(bytes(cert_value[0]), default_backend())
                    print(f"   Issuer:  {cert_der.issuer}")
                    print(f"   Subject: {cert_der.subject}")
                    print(f"   Valid:   {cert_der.not_valid_before_utc} → {cert_der.not_valid_after_utc}")
                    cert_pem = cert_der.public_bytes(serialization.Encoding.PEM)
                    print(f"   PEM:\n{cert_pem.decode()}")
            except PyKCS11.PyKCS11Error as e:
                print(f"Error retrieving attributes: {e}")
    except PyKCS11.PyKCS11Error as e:
        print(f"Error retrieving certificates: {e}")


def list_private_keys():
    try:
        priv_keys = pkcs11.get_private_keys()
        print(f"Found {len(priv_keys)} private key(s).")
        for priv_key in priv_keys:
            try:
                attrs = pkcs11.get_session().getAttributeValue(priv_key, [PyKCS11.CKA_LABEL], allAsBinary=False)
                label = attrs[0] if attrs and attrs[0] else "Unknown Label"
                print(f" - Private key Label: {label}")
                id_value = pkcs11.get_session().getAttributeValue(priv_key, [PyKCS11.CKA_ID], allAsBinary=False)
                if id_value:
                    hex_string = ''.join(f'{byte:02X}' for byte in id_value[0])
                    print(f" - ID value: {hex_string}")
            except PyKCS11.PyKCS11Error as e:
                print(f"Error retrieving attributes: {e}")
    except PyKCS11.PyKCS11Error as e:
        print(f"Error retrieving private keys: {e}")


def main():
    try:
        token_info = pkcs11.get_token_info()
        print("\nToken Info:")
        for key, value in token_info.items():
            print(f" - {key}: {value}")

        pin = "Wisekey1!"
        pkcs11.open_session(pin)
        print("\nSession opened successfully.")

        print("\n1. Listing certificates:")
        list_certificates()

        print("\n2. Listing private keys:")
        list_private_keys()

    except Exception as e:
        print(f"\nUnexpected error: {e}")
    finally:
        pkcs11.close_session()
        print("\nSession closed.")


if __name__ == "__main__":
    main()
