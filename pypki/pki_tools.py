import json
import math
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem
from asn1crypto.core import BitString, OctetBitString
from ipaddress import ip_address
from datetime import datetime, timedelta, timezone
from pypki.ca import CertificationAuthority
import PyKCS11
from pypki.pkcs11_helper import PKCS11Helper

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

    @staticmethod
    def get_revocation_reason(reason_code):
        """Return the reason description based on reason code."""
        return PKITools.REVOCATION_REASONS.get(reason_code, "Unknown Reason")


#
# Key Tools Class
#
class KeyTools:
    def __init__(
        self,
        private_key: bytes = None,
        key_id: str = None,
        slot_num: int = None,
        token_password: str = ""
    ):
        self.__private_key: bytes = private_key
        if key_id is not None:
            self.__key_id: str = key_id
            self.__slot_num: int = slot_num
            self.__token_password: str = token_password
            self.__pkcs11 = PKCS11Helper()
            self.__pkcs11.open_session(token_password)
            self.__token_key = self.__pkcs11.get_key_by_id(key_id)
        else:
            self.__key_id = None
        pass

    def is_hsm(self):
        return self.__key_id is not None

    def generate_private_key(self, algorithm: str, key_type: str) -> bytes:
        """
        Generate a private key in PEM format.
        :param algorithm: "RSA" or "ECDSA"
        :param key_type: For RSA (2048, 3072, 4096), for ECDSA (P-256, P-384, P-521)
        :return: Private key in PEM format
        """
        if algorithm == "RSA":
            key_size = int(key_type)
            if key_size not in [2048, 3072, 4096]:
                raise ValueError("Invalid RSA key size")
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=key_size
            )

        elif algorithm == "ECDSA":
            curve_mapping = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
            }
            if key_type not in curve_mapping:
                raise ValueError("Invalid ECDSA curve")
            private_key = ec.generate_private_key(curve_mapping[key_type])

        else:
            raise ValueError("Unsupported algorithm")

        self.__private_key = private_key

        return self.__private_key


    def get_private_key(self):
        """Returns the private key in a controlled manner."""
        if self.__private_key:
            return self.__private_key
        else:
            return None
        

    def set_private_key(self, private_key: bytes):
        self.__private_key = private_key
        pass


    def get_public_key(self):
        """Returns the public key in a controlled manner."""
        if self.__private_key:
            return self.__private_key.public_key()
        else:
            return None


    def get_private_key_pem(self, password: bytes = None):
        """
        Securely exports the private key in PEM format.
        If a password is provided, the key is encrypted.
        """
        if self.__private_key:
            encryption_algorithm = (
                serialization.BestAvailableEncryption(password)
                if password else serialization.NoEncryption()
            )
            
            return self.__private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
        else:
            return None


    def get_public_key_pem(self):
        """Returns the public key in a controlled manner."""
        if self.__private_key:
            return self.__private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            return None


    def sign_digest(
        self, 
        tbs_digest: bytes
    ):
        
        #tbs_digest = b'\xcf\xcbS\xdb\x8a\xeeK\x8fP0\x96A^*9%\x93\xe6\x97\x83Q2\xd2\x95\x1cJ#\xf4\xa3k\xf0M'
        
        if not self.is_hsm():
            # Software key
            if isinstance(self.__private_key, rsa.RSAPrivateKey):
                # RSA: PKCS#1 v1.5 with SHA-256
                signature = self.__private_key.sign(
                    tbs_digest,
                    padding.PKCS1v15(),
                    Prehashed(hashes.SHA256())
                )
            elif isinstance(self.__private_key, ec.EllipticCurvePrivateKey):
                # ECC: ECDSA with SHA-256
                signature = self.__private_key.sign(
                    tbs_digest,
                    ec.ECDSA(Prehashed(hashes.SHA256()))
                )
            else:
                raise ValueError("Unsupported key type: {}".format(type(self.__private_key)))
        else:
            # Hardware key
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS_PSS, None)
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_OAEP, None)
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_PSS, None)
            signature = bytes(self.__pkcs11.get_session().sign(self.__token_key, tbs_digest, mechanism))

            #raw_signature = bytes(self.__pkcs11.get_session().sign(self.__token_key, tbs_digest, mechanism))
            #signature = OctetBitString(raw_signature).dump()

        if signature:
            #print(signature)
            return signature
        else:
            raise ValueError("Problem signing the digest")
            


#
# Certificate Tools Class
#
class CertificateTools:
    def __init__(self):
        """Initialize the PKI Utilities class."""
        self.__request__ = {}
        self.__template__ = {}
        pass

    def load_certificate_template(self, template_json: str):
        self.__template__ = json.loads(template_json)
        pass

    def load_certificate_request(self, request_json: str):
        self.__request__ = json.loads(request_json)
        pass

    def build_subject(self):
        """
        Buld the subject extension based in the loaded template and request
        """
        # Ensure subject fields are set correctly
        subject_attrs = []
        for field, details in self.__template__["subject_name"]["fields"].items():
            value = self.__request__["subject_name"].get(field, details.get("default", ""))
            if details.get("mandatory", False) and not value:
                raise ValueError(f"Missing mandatory field: {field}")
            if value:
                subject_attrs.append(x509.NameAttribute(PKITools.OID_MAPPING[field], value))
        return x509.Name(subject_attrs)


    def build_san(self):
        """
        Buld the SAN extension based in the loaded template and request
        """
        alt_names = []

        san_config = self.__template__["extensions"]["subjectAltName"]["allowed_types"]
        
        if "subjectAltName" in self.__request__:
            san_request = self.__request__["subjectAltName"]
            
            # Process DNS names
            if "dnsNames" in san_request and san_config["dnsNames"]["allowed"]:
                dns_names = san_request["dnsNames"]
                if not (san_config["dnsNames"]["min"] <= len(dns_names) <= san_config["dnsNames"]["max"]):
                    raise ValueError("Number of DNS names out of allowed range")
                alt_names.extend([x509.DNSName(name) for name in dns_names])
            
            # Process IP addresses
            if "ipAddresses" in san_request and san_config["ipAddresses"]["allowed"]:
                ip_addresses = san_request["ipAddresses"]
                if not (san_config["ipAddresses"]["min"] <= len(ip_addresses) <= san_config["ipAddresses"]["max"]):
                    raise ValueError("Number of IP addresses out of allowed range")
                try:
                    alt_names.extend([x509.IPAddress(ip_address(ip)) for ip in ip_addresses])
                except ValueError:
                    raise ValueError("Invalid IP address format")
        
        return alt_names


    def build_template_extensions(self, builder, public_key: bytes, issuing_ca: CertificationAuthority = None):
        """
        Add extensions based in the loaded template
        """
        if "extensions" in self.__template__:
            # Subject Alternative Name (SAN) NOT CORRECT!!!
            # Key Usage
            if "keyUsage" in self.__template__["extensions"]:
                key_usage_values = self.__template__["extensions"]["keyUsage"]["values"]
                key_usage = x509.KeyUsage(
                    digital_signature="digitalSignature" in key_usage_values,
                    key_encipherment="keyEncipherment" in key_usage_values,
                    key_cert_sign="keyCertSign" in key_usage_values,
                    crl_sign="cRLSign" in key_usage_values,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                )
                builder = builder.add_extension(key_usage, critical=self.__template__["extensions"]["keyUsage"]["critical"])

            # "basicConstraints": { "critical": true, "ca": false, "pathLen": null },
            if "basicConstraints" in self.__template__["extensions"]:

                # Extract the basicConstraints field
                basic_constraints = self.__template__["extensions"]["basicConstraints"]
                
                # Get values
                critical = basic_constraints.get("critical", False)
                ca = basic_constraints.get("ca", False)
                path_len = basic_constraints.get("pathLen", None)
                
                # Convert pathLen null to Python None explicitly
                # path_length = "None" if path_len is None else path_len
                # csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                builder = builder.add_extension(x509.BasicConstraints(ca, path_len), critical)

            if "policyIdentifiers" in self.__template__["extensions"]:
                policy_information = []
                for policy_oid in self.__template__["extensions"]["policyIdentifiers"]["values"]:
                    # Create PolicyInformation objects for each policy
                    policy_information.append(x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), []))

                policy = x509.CertificatePolicies(policy_information)
                builder = builder.add_extension(policy, critical=self.__template__["extensions"]["policyIdentifiers"]["critical"])
            
            # AIA extension can include OCSP URI and/or CA Issuers URI
            if "aia" in self.__template__["extensions"]:
                aia_list =[]
                if "OCSP" in self.__template__["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.1'), x509.UniformResourceIdentifier(self.__template__["extensions"]["aia"]["authorityInfoAccess"]["OCSP"]["url"])))
                if "caIssuers" in self.__template__["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.2'), x509.UniformResourceIdentifier(self.__template__["extensions"]["aia"]["authorityInfoAccess"]["caIssuers"]["url"])))

                aia = x509.AuthorityInformationAccess(aia_list)
                builder = builder.add_extension(aia, critical = self.__template__["extensions"]["aia"]["critical"])

            # Add CDP (Certificate Distribution Points)
            if "cdp" in self.__template__["extensions"]:
                cdp_uri = self.__template__["extensions"]["cdp"]["url"]
                cdp = x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ])
                builder = builder.add_extension(cdp, critical=self.__template__["extensions"]["cdp"]["critical"])

            # Extended Key Usage
            if "extendedKeyUsage" in self.__template__["extensions"]:
                eku_values = self.__template__["extensions"]["extendedKeyUsage"]["allowed"]
                eku_oids = {
                    "serverAuth": x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    "clientAuth": x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    "emailProtection": x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    "codeSigning": x509.ExtendedKeyUsageOID.CODE_SIGNING,
                    "timeStamping": x509.ExtendedKeyUsageOID.TIME_STAMPING,
                }
                eku_list = [eku_oids[usage] for usage in eku_values if usage in eku_oids]
                if eku_list:
                    builder = builder.add_extension(x509.ExtendedKeyUsage(eku_list), critical=self.__template__["extensions"]["extendedKeyUsage"]["critical"])

            # Subject Key Identifier (SKI)
            ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
            if "subjectKeyIdentifier" in self.__template__["extensions"]:
                builder = builder.add_extension(ski, critical=False)

            # Authority Key Identifier (SKI)
            if "authorityKeyIdentifier" in self.__template__["extensions"]:
                if self.__template__["extensions"]["authorityKeyIdentifier"]["include"]:
                    if issuing_ca is None:
                        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
                    else:
                        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuing_ca.get_certificate().public_key())
                    builder = builder.add_extension(aki, critical=self.__template__["extensions"]["authorityKeyIdentifier"]["critical"])

        return builder


    def generate_csr_pem(
        self,
        request_json: str,
        certificate_key: KeyTools,
        issuing_ca: CertificationAuthority = None
    ) -> bytes:
        """
        Generate a CSR based on the object's private key, template, and request data.
        :return: CSR in PEM format
        """

        self.load_certificate_request(request_json=request_json)

        subject = self.build_subject()

        # Build CSR with Subject
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        csr_builder = self.build_template_extensions(csr_builder, certificate_key.get_public_key(), issuing_ca)

        # Add Request Extensions
        if "extensions" in self.__template__:
            # Subject Alternative Name (SAN)
            if "subjectAltName" in self.__request__:
                alt_names = self.build_san()
                if alt_names:
                    csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=self.__template__["extensions"]["subjectAltName"]["critical"])

        # ✅ Sign CSR
        csr = csr_builder.sign(certificate_key.get_private_key(), hashes.SHA256())

        return csr.public_bytes(serialization.Encoding.PEM)
    

    def patch_certificate_signature(self, pre_cert_der: bytes, real_signature: bytes, is_ecdsa: bool = False, public_key: bytes = None) -> bytes:
        """
        Replace the dummy signature in a DER-encoded cert with the actual one.

        Args:
            pre_cert_der: DER-encoded certificate with dummy signature.
            real_signature: The correct signature (raw r||s for ECDSA, or raw bytes for RSA).
            is_ecdsa: Whether the signature is ECDSA (if True, it will be DER-encoded).

        Returns:
            The final DER-encoded certificate with the real signature.
        """
        cert = asn1_x509.Certificate.load(pre_cert_der)

        if is_ecdsa:
#            half = len(real_signature) // 2
#            r = int.from_bytes(real_signature[:half], byteorder='big')
#            s = int.from_bytes(real_signature[half:], byteorder='big')
            r, s = decode_dss_signature(real_signature)
            der_sig = encode_dss_signature(r, s)
        else:
            der_sig = real_signature

        # Now we can create a BitString from the binary signature with 0 unused bits
        cert['signature_value'] = OctetBitString(der_sig)

        return cert.dump()



    def generate_certificate_from_csr(
        self, 
        csr_pem: bytes,
        issuing_ca: CertificationAuthority = None,
        certificate_key: KeyTools = None,
        validity_days: int = 365
    ) -> x509.Certificate:
        
        csr = x509.load_pem_x509_csr(csr_pem)

        subject = csr.subject

        # Set notValidBefore and notValidAfter
        not_valid_before = datetime.now(timezone.utc)
        max_validity = self.__template__["max_validity"]
        if max_validity > PKITools.INFINITE_VALIDITY:
            if (validity_days > max_validity) or (validity_days == PKITools.INFINITE_VALIDITY):
                validity_days = max_validity
        if validity_days > -1:
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
        else:
            not_valid_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # GeneralizedTime format

        if issuing_ca is None and certificate_key is None:
            raise ValueError("Missing signing key information")

        if issuing_ca is None:
            signing_private_key = certificate_key
            issuer = subject 
            serial_number = x509.random_serial_number()
        else:
            signing_private_key = issuing_ca.get_signing_key()
            issuer = issuing_ca.get_certificate().subject
            serial_number = issuing_ca.generate_unique_serial()
            # Check if the validity surpasses the CA
            ca_validity = issuing_ca.get_certificate().not_valid_after_utc
            if not_valid_after > ca_validity:
                not_valid_after = ca_validity

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )

        # ✅ Copy all extensions from the CSR
        for ext in csr.extensions:
            cert_builder = cert_builder.add_extension(ext.value, ext.critical)

        # Use a temporary key to generate the TBS certificate bytes
        if signing_private_key.is_hsm() or isinstance(signing_private_key.get_private_key(), rsa.RSAPrivateKey):
            dummy_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=None
            )
        else:
            dummy_private_key = ec.generate_private_key(
                ec.SECP256R1(),  # NIST P-256 TODO: THIS IS INCOMPLETE
                backend=None
            )

        pre_cert = cert_builder.sign(
            private_key=dummy_private_key,
            algorithm=hashes.SHA256(),
            backend=None
        )
        tbs_cert_bytes = pre_cert.tbs_certificate_bytes

        # 🔹 Correct Signing: Hash the TBS certificate bytes
        digest = hashes.Hash(hashes.SHA256(), backend=None)
        digest.update(tbs_cert_bytes)
        tbs_digest = digest.finalize()  # This is what we actually sign

        #tbs_digest = b'\xf9t\x89\x17O\xbb\xe1\xb5@\x91\xf0w#$\xfe\x14\xf5\xe5\xd0LPeB\xb4\xfdo\xfc}\xbd\x7f\xbe\xd3'

        # 🔹 Generate the actual signature using the signing key
        signature = signing_private_key.sign_digest(tbs_digest)

        # 🔹 Replace the incorrect signature with the real PKCS#11 signature
        final_cert = x509.load_der_x509_certificate(
            pre_cert.public_bytes(serialization.Encoding.DER), backend=None
        )

        if signing_private_key.is_hsm() or isinstance(signing_private_key.get_private_key(), rsa.RSAPrivateKey):
            final_der = self.patch_certificate_signature(
                pre_cert_der=pre_cert.public_bytes(serialization.Encoding.DER),
                real_signature=signature,          # raw signature (r||s for ECDSA, or RSA sig)
                is_ecdsa=False                      # set False if RSA
            )
        else:
            final_der = self.patch_certificate_signature(
                pre_cert_der=pre_cert.public_bytes(serialization.Encoding.DER),
                real_signature=signature,          # raw signature (r||s for ECDSA, or RSA sig)
                public_key=signing_private_key.get_public_key(),
                is_ecdsa=True                      # set False if RSA
            )

        # Convert final cert to PEM format
        final_cert = x509.load_der_x509_certificate(final_der)

        return final_cert




    def generate_certificate_from_csr_old(
        self, 
        csr_pem: bytes,
        issuing_ca: CertificationAuthority = None,
        certificate_key: KeyTools = None,
        validity_days: int = 365
    ) -> x509.Certificate:
        
        csr = x509.load_pem_x509_csr(csr_pem)

        subject = csr.subject

        # Set notValidBefore and notValidAfter
        not_valid_before = datetime.now(timezone.utc)
        max_validity = self.__template__["max_validity"]
        if max_validity > PKITools.INFINITE_VALIDITY:
            if (validity_days > max_validity) or (validity_days == PKITools.INFINITE_VALIDITY):
                validity_days = max_validity
        if validity_days > -1:
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
        else:
            not_valid_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # GeneralizedTime format

        if issuing_ca is None and certificate_key is None:
            raise ValueError("Missing signing key information")

        if issuing_ca is None:
            signing_private_key = certificate_key
            issuer = subject 
            serial_number = x509.random_serial_number()
        else:
            signing_private_key = issuing_ca.get_signing_key()
            issuer = issuing_ca.get_certificate().subject
            serial_number = issuing_ca.generate_unique_serial()
            # Check if the validity surpasses the CA
            ca_validity = issuing_ca.get_certificate().not_valid_after_utc
            if not_valid_after > ca_validity:
                not_valid_after = ca_validity

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )

        # ✅ Copy all extensions from the CSR
        for ext in csr.extensions:
            cert_builder = cert_builder.add_extension(ext.value, ext.critical)

        # Use a temporary key to generate the TBS certificate bytes
        if isinstance(signing_private_key.get_private_key(), rsa.RSAPrivateKey):
            dummy_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=None
            )
        else:
            dummy_private_key = ec.generate_private_key(
                ec.SECP256R1(),  # NIST P-256 TODO: THIS IS INCOMPLETE
                backend=None
            )

        pre_cert = cert_builder.sign(
            private_key=dummy_private_key,
            algorithm=hashes.SHA256(),
            backend=None
        )
        tbs_cert_bytes = pre_cert.tbs_certificate_bytes

        # 🔹 Correct Signing: Hash the TBS certificate bytes
        digest = hashes.Hash(hashes.SHA256(), backend=None)
        digest.update(tbs_cert_bytes)
        tbs_digest = digest.finalize()  # This is what we actually sign

        # 🔹 Generate the actual signature using the signing key
        signature = signing_private_key.sign_digest(tbs_digest)

        # 🔹 Replace the incorrect signature with the real PKCS#11 signature
        final_cert = x509.load_der_x509_certificate(
            pre_cert.public_bytes(serialization.Encoding.DER), backend=None
        )

        final_cert_bytes = bytearray(final_cert.public_bytes(serialization.Encoding.DER))

        if isinstance(signing_private_key.get_private_key(), rsa.RSAPrivateKey):
            # 🔹 Manually patch the signature
            final_cert_bytes[-len(signature):] = signature  # Replace with real signature
        else:
            # Assuming `signature` is raw r||s bytes (like from PKCS#11)
            r = int.from_bytes(signature[:len(signature)//2], byteorder='big')
            s = int.from_bytes(signature[len(signature)//2:], byteorder='big')

            # DER-encode the r,s pair
            der_encoded_signature = encode_dss_signature(r, s)
            final_cert_bytes[-len(der_encoded_signature):] = der_encoded_signature

        # Convert final cert to PEM format
        final_cert = x509.load_der_x509_certificate(bytes(final_cert_bytes), backend=None)

        return final_cert
    

    def generate_certificate_pem_from_csr(
        self, 
        csr_pem: bytes,
        issuing_ca: CertificationAuthority = None,
        certificate_key: KeyTools = None,
        validity_days: int = 365
    ) -> bytes:

        certificate = self.generate_certificate_from_csr(
            csr_pem=csr_pem, 
            issuing_ca=issuing_ca, 
            certificate_key=certificate_key,
            validity_days=validity_days)

        return certificate.public_bytes(serialization.Encoding.PEM)


    def generate_certificate(
        self,
        request_json: str,
        issuing_ca: CertificationAuthority = None,
        certificate_key: KeyTools = None,
        validity_days: int = 365
    ) -> bytes:
        
        csr_pem = self.generate_csr_pem(request_json=request_json, certificate_key=certificate_key, issuing_ca=issuing_ca)

        return self.generate_certificate_from_csr(csr_pem=csr_pem, issuing_ca=issuing_ca, certificate_key=certificate_key, validity_days=validity_days)


    def generate_certificate_pem(
        self,
        request_json: str,
        issuing_ca: CertificationAuthority = None,
        certificate_key: KeyTools = None,
        validity_days: int = 365
    ) -> bytes:
        
        certificate = self.generate_certificate(
            request_json=request_json,
            issuing_ca=issuing_ca,
            certificate_key=certificate_key,
            validity_days=validity_days
        )

        return certificate.public_bytes(serialization.Encoding.PEM)


    # Generate PKCS#12 bundle
    def generate_pkcs12(
        self,
        request_json: str,
        issuing_ca: CertificationAuthority = None,
        certificate_key: KeyTools = None,
        validity_days: int = 365,
        pfx_password: bytes = b"",
        friendly_name: bytes = b"MyCert",
        key_algorithm: str = "RSA",
        key_type: str = "2048"
    ) -> bytes:
        
        if issuing_ca is None:
            ca_certs = None
        else:
            ca_certs_pem = issuing_ca.get_certificate_chain_pem()
            ca_certs = self.load_ca_certificates(pem_data=ca_certs_pem)

        certificate_key = KeyTools()
        certificate_key.generate_private_key(key_algorithm, key_type)

        certificate = self.generate_certificate(
            request_json=request_json,
            issuing_ca=issuing_ca, 
            certificate_key=certificate_key, 
            validity_days=validity_days
        )

        p12 = pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=certificate_key.get_private_key(),
            cert=certificate,
            cas=ca_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password)
        )
        return p12


    def load_ca_certificates(self, pem_data: str):
        # Split the PEM chain into individual certs
        certs = []
        for cert in pem_data.split(b"-----END CERTIFICATE-----"):
            if b"-----BEGIN CERTIFICATE-----" in cert:
                cert += b"-----END CERTIFICATE-----\n"
                x509_cert = x509.load_pem_x509_certificate(cert, None)
                certs.append(x509_cert)
        return certs