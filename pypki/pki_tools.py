from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID, ExtensionOID

class PKITools:
    INFINITE_VALIDITY = -1 
            # ✅ Fixed OID Mapping for Subject Fields
    OID_MAPPING = {
        # Subject Name Attributes
        "commonName": NameOID.COMMON_NAME,  # 2.5.4.3
        "organizationName": NameOID.ORGANIZATION_NAME,  # 2.5.4.10
        "organizationalUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,  # 2.5.4.11
        "countryName": NameOID.COUNTRY_NAME,  # 2.5.4.6
        "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,  # 2.5.4.8
        "localityName": NameOID.LOCALITY_NAME,  # 2.5.4.7
        "emailAddress": NameOID.EMAIL_ADDRESS,  # 1.2.840.113549.1.9.1
        "serialNumber": NameOID.SERIAL_NUMBER,  # 2.5.4.5
        "givenName": NameOID.GIVEN_NAME,  # 2.5.4.42
        "surname": NameOID.SURNAME,  # 2.5.4.4
        "title": NameOID.TITLE,  # 2.5.4.12
        "businessCategory": NameOID.BUSINESS_CATEGORY,  # 2.5.4.15
        "postalCode": NameOID.POSTAL_CODE,  # 2.5.4.17
        "streetAddress": NameOID.STREET_ADDRESS,  # 2.5.4.9

        # Key Usage OIDs (2.5.29.15)
        "digitalSignature": ObjectIdentifier("2.5.29.15.0"),
        "nonRepudiation": ObjectIdentifier("2.5.29.15.1"),  # Also known as contentCommitment
        "keyEncipherment": ObjectIdentifier("2.5.29.15.2"),
        "dataEncipherment": ObjectIdentifier("2.5.29.15.3"),
        "keyAgreement": ObjectIdentifier("2.5.29.15.4"),
        "keyCertSign": ObjectIdentifier("2.5.29.15.5"),
        "cRLSign": ObjectIdentifier("2.5.29.15.6"),
        "encipherOnly": ObjectIdentifier("2.5.29.15.7"),
        "decipherOnly": ObjectIdentifier("2.5.29.15.8"),

        # Extended Key Usage OIDs (2.5.29.37)
        "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,  # 1.3.6.1.5.5.7.3.1
        "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,  # 1.3.6.1.5.5.7.3.2
        "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,  # 1.3.6.1.5.5.7.3.3
        "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,  # 1.3.6.1.5.5.7.3.4
        "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,  # 1.3.6.1.5.5.7.3.8
        "ocspSigning": ExtendedKeyUsageOID.OCSP_SIGNING,  # 1.3.6.1.5.5.7.3.9
        "smartCardLogon": ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),  # Microsoft-specific
        "documentSigning": ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"),  # Microsoft document signing
        "anyExtendedKeyUsage": ObjectIdentifier("2.5.29.37.0"),  # Any extended key usage
    }


    # Revocation Reasons (RFC 5280)
    REVOCATION_REASONS = {
        "unspecified" : 0,  # No specific reason given
        "keyCompromise" : 1,  # Private key may have been compromised
        "cACompromise" : 2,  # Certificate Authority key compromised
        "affiliationChanged" : 3,  # Subject's organization has changed
        "superseded" : 4,  # Certificate replaced with a new one
        "cessationOfOperation" : 5,  # Entity no longer exists
        "certificateHold" : 6,  # Temporary hold
        "removeFromCRL" : 8,  # Used only in delta CRLs
        "privilegeWithdrawn" : 9,  # Privileges revoked
        "aACompromise" : 10  # Attribute Authority compromised
    }

    REVOCATION_REASON_MAPPING = {
        0: x509.ReasonFlags.unspecified,
        1: x509.ReasonFlags.key_compromise,
        2: x509.ReasonFlags.ca_compromise,
        3: x509.ReasonFlags.affiliation_changed,
        4: x509.ReasonFlags.superseded,
        5: x509.ReasonFlags.cessation_of_operation,
        6: x509.ReasonFlags.certificate_hold,
        8: x509.ReasonFlags.remove_from_crl,
        9: x509.ReasonFlags.privilege_withdrawn,
        10: x509.ReasonFlags.aa_compromise,
    }

    @classmethod
    def get_revocation_reason(self, reason_code):
        """Return the reason description based on reason code."""
        return self.REVOCATION_REASONS.get(reason_code, "Unknown Reason")


    @classmethod
    def get_oid_name(cls, oid: ObjectIdentifier) -> str:
        for name, known_oid in cls.OID_MAPPING.items():
            if oid == known_oid:
                return name
        return oid.dotted_string
    

    @classmethod
    def parse_csr_to_json(self, csr: bytes) -> dict:
        #csr = x509.load_pem_x509_csr(pem_csr.encode())

        # Extract subject fields
        subject = {}
        for attr in csr.subject:
            key = self.get_oid_name(attr.oid)
            subject[key] = attr.value

        # Extract SAN
        san = {}
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_value = san_ext.value

            dns_names = san_value.get_values_for_type(x509.DNSName)
            if dns_names:
                san["dnsNames"] = dns_names

            ip_addresses = san_value.get_values_for_type(x509.IPAddress)
            if ip_addresses:
                san["ipAddresses"] = [str(ip) for ip in ip_addresses]

            email_addresses = san_value.get_values_for_type(x509.RFC822Name)
            if email_addresses:
                san["emailAddresses"] = email_addresses

            uris = san_value.get_values_for_type(x509.UniformResourceIdentifier)
            if uris:
                san["uniformResourceIdentifiers"] = [str(uri) for uri in uris]

        except x509.ExtensionNotFound:
            pass  # SAN not present

        return {
            "subject_name": subject,
            "subjectAltName": san
        }