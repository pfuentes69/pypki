import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pypki.pkcs11_helper import PKCS11Helper  # Ensure this is your class

pkcs11 = PKCS11Helper()

def list_certificates():
    try:
        certs = pkcs11.get_certificates()
        print(f"🔍 Found {len(certs)} certificate(s).")

        if not certs:
            print("⚠️ No certificates found.")

        for cert in certs:
            try:
                # print(f"🛠️ Inspecting object:")
                # print(cert)
                
                # Get attributes (SafeNet may not support all)
                attrs = pkcs11.get_session().getAttributeValue(cert, [PyKCS11.CKA_LABEL], allAsBinary=False)
                label = attrs[0] if attrs and attrs[0] else "Unknown Label"
                print(f" - ✅ Certificate Label: {label}")
                id_value = pkcs11.get_session().getAttributeValue(cert, [PyKCS11.CKA_ID], allAsBinary=False)
                if id_value:
                    # Convert each byte to a two-character hex string and join them
                    hex_string = ''.join(f'{byte:02X}' for byte in id_value[0])
                print(f" - ✅ ID value: {hex_string}")
                cert_value = pkcs11.get_session().getAttributeValue(cert, [PyKCS11.CKA_VALUE], allAsBinary=False)
                print(" - ✅ Certificate value:")
                if cert_value:
                    # Decode the certificate from raw DER format
                    cert_der = x509.load_der_x509_certificate(bytes(cert_value[0]), default_backend())

                    # Print the issuer and subject
                    print(f"Issuer: {cert_der.issuer}")
                    print(f"Subject: {cert_der.subject}")

                    # Print the validity period
                    print(f"Start date: {cert_der.not_valid_before_utc}")
                    print(f"End date: {cert_der.not_valid_after_utc}")

                    # Optionally, convert the certificate to PEM format for easy inspection
                    cert_pem = cert_der.public_bytes(serialization.Encoding.PEM)
                    print(f"PEM Format:\n{cert_pem.decode()}")
                else:
                    print("Empty certificate value")
            except PyKCS11.PyKCS11Error as e:
                print(f"❌ Error retrieving attributes: {e}")
    except PyKCS11.PyKCS11Error as e:
        print(f"❌ Error retrieving certificates: {e}")


def list_private_keys():
    try:
        priv_keys = pkcs11.get_private_keys()
        print(f"🔍 Found {len(priv_keys)} Private Key(s).")

        if not priv_keys:
            print("⚠️ No private keys found.")

        for priv_key in priv_keys:
            try:
                # print(f"🛠️ Inspecting object:")
                # print(priv_key)

                # Get attributes (SafeNet may not support all)
                attrs = pkcs11.get_session().getAttributeValue(priv_key, [PyKCS11.CKA_LABEL], allAsBinary=False)
                label = attrs[0] if attrs and attrs[0] else "Unknown Label"
                print(f" - ✅ Private key Label: {label}")
                id_value = pkcs11.get_session().getAttributeValue(priv_key, [PyKCS11.CKA_ID], allAsBinary=False)
                if id_value:
                    # Convert each byte to a two-character hex string and join them
                    hex_string = ''.join(f'{byte:02X}' for byte in id_value[0])
                print(f" - ✅ ID value: {hex_string}")
            except PyKCS11.PyKCS11Error as e:
                print(f"❌ Error retrieving attributes: {e}")
    except PyKCS11.PyKCS11Error as e:
        print(f"❌ Error retrieving private keys: {e}")


def main():

    try:
        # Get token info
        token_info = pkcs11.get_token_info()
        print("\n💾 Token Info:")
        for key, value in token_info.items():
            print(f" - {key}: {value}")

        # Step 1: Open session
#        pin = getpass.getpass("Enter SafeNet Token PIN: ")
        pin = "Wisekey1!"
        pkcs11.open_session(pin)
        print("\n🔓 Session opened successfully.")

        # Step 2: List certificates
        print("\n📜 Listing content:")

        print("\n📜 1. Listing certificates:")
        list_certificates()

        print("\n📜 2. Listing private keys:")
        list_private_keys()

        # print("\n📜 3. Create private key")
        # ck_id = pkcs11.generate_private_key(label="Test")
        # print(f"CK ID of new key: {ck_id}")

        print("\n📜 4. Listing private keys:")
        list_private_keys()

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

    finally:
        pkcs11.close_session()
        print("\n🔒 Session closed.")

if __name__ == "__main__":
    main()
