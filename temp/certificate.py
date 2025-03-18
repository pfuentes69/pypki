import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from ipaddress import ip_address
from datetime import datetime, timedelta, timezone
from pypki.pki_tools import PKITools
from pypki.ca import CertificationAuthority


class Certificate:
    def __init__(self):
        """Initialize the PKI Utilities class."""
        self.template = {}
        self.request = {}
        self.private_key: bytes = b""
        self.private_key_pem: bytes = b""
        self.public_key: bytes = b""
        pass

    def load_certificate_template(self, template_json: str):
        self.template = json.loads(template_json)
        pass

    def load_certificate_request(self, request_json: str):
        self.request = json.loads(request_json)
        pass

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

        self.private_key = private_key
        self.public_key = private_key.public_key()

        return self.private_key
    
    def get_private_key(self):
        """Returns the private key in a controlled manner."""
        return self.private_key

    def export_private_key(self, password: bytes = None):
        """
        Securely exports the private key in PEM format.
        If a password is provided, the key is encrypted.
        """
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

    def get_subject(self):
        """
        Buld the subject extension based in the loaded template and request
        """
        # Ensure subject fields are set correctly
        subject_attrs = []
        for field, details in self.template["subject_name"]["fields"].items():
            value = self.request["subject_name"].get(field, details.get("default", ""))
            if details.get("mandatory", False) and not value:
                raise ValueError(f"Missing mandatory field: {field}")
            if value:
                subject_attrs.append(x509.NameAttribute(PKITools.OID_MAPPING[field], value))
        return x509.Name(subject_attrs)


    def get_san(self):
        """
        Buld the SAN extension based in the loaded template and request
        """

        """
        # Basic version
        alt_names = []
        if "dnsNames" in self.request["subjectAltName"]:
            alt_names.extend([x509.DNSName(name) for name in self.request["subjectAltName"]["dnsNames"]])
        if "ipAddresses" in self.request["subjectAltName"]:
            alt_names.extend([x509.IPAddress(name) for name in self.request["subjectAltName"]["ipAddresses"]])

        return alt_names
        """

        alt_names = []

        san_config = self.template["extensions"]["subjectAltName"]["allowed_types"]
        
        if "subjectAltName" in self.request:
            san_request = self.request["subjectAltName"]
            
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


    def add_template_extensions(self, builder, issuing_ca: CertificationAuthority = None):
        """
        Add extensions based in the loaded template
        """
        if "extensions" in self.template:
            # Subject Alternative Name (SAN) NOT CORRECT!!!
            # Key Usage
            if "keyUsage" in self.template["extensions"]:
                key_usage_values = self.template["extensions"]["keyUsage"]["values"]
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
                builder = builder.add_extension(key_usage, critical=self.template["extensions"]["keyUsage"]["critical"])

            # "basicConstraints": { "critical": true, "ca": false, "pathLen": null },
            if "basicConstraints" in self.template["extensions"]:

                # Extract the basicConstraints field
                basic_constraints = self.template["extensions"]["basicConstraints"]
                
                # Get values
                critical = basic_constraints.get("critical", False)
                ca = basic_constraints.get("ca", False)
                path_len = basic_constraints.get("pathLen", None)
                
                # Convert pathLen null to Python None explicitly
                # path_length = "None" if path_len is None else path_len
                # csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                builder = builder.add_extension(x509.BasicConstraints(ca, path_len), critical)

            if "policyIdentifiers" in self.template["extensions"]:
                policy_information = []
                for policy_oid in self.template["extensions"]["policyIdentifiers"]["values"]:
                    # Create PolicyInformation objects for each policy
                    policy_information.append(x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), []))

                policy = x509.CertificatePolicies(policy_information)
                builder = builder.add_extension(policy, critical=self.template["extensions"]["policyIdentifiers"]["critical"])
            
            # AIA extension can include OCSP URI and/or CA Issuers URI
            if "aia" in self.template["extensions"]:
                aia_list =[]
                if "OCSP" in self.template["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.1'), x509.UniformResourceIdentifier(self.template["extensions"]["aia"]["authorityInfoAccess"]["OCSP"]["url"])))
                if "caIssuers" in self.template["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.2'), x509.UniformResourceIdentifier(self.template["extensions"]["aia"]["authorityInfoAccess"]["caIssuers"]["url"])))

                aia = x509.AuthorityInformationAccess(aia_list)
                builder = builder.add_extension(aia, critical = self.template["extensions"]["aia"]["critical"])

            # Add CDP (Certificate Distribution Points)
            if "cdp" in self.template["extensions"]:
                cdp_uri = self.template["extensions"]["cdp"]["url"]
                cdp = x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ])
                builder = builder.add_extension(cdp, critical=self.template["extensions"]["cdp"]["critical"])

            # Extended Key Usage
            if "extendedKeyUsage" in self.template["extensions"]:
                eku_values = self.template["extensions"]["extendedKeyUsage"]["allowed"]
                eku_oids = {
                    "serverAuth": x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    "clientAuth": x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    "emailProtection": x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    "codeSigning": x509.ExtendedKeyUsageOID.CODE_SIGNING,
                    "timeStamping": x509.ExtendedKeyUsageOID.TIME_STAMPING,
                }
                eku_list = [eku_oids[usage] for usage in eku_values if usage in eku_oids]
                if eku_list:
                    builder = builder.add_extension(x509.ExtendedKeyUsage(eku_list), critical=self.template["extensions"]["extendedKeyUsage"]["critical"])

            # Authority Key Identifier (SKI)
            if "authorityKeyIdentifier" in self.template["extensions"]:
                if self.template["extensions"]["authorityKeyIdentifier"]["include"]:
                    if issuing_ca is None:
                        aki = x509.AuthorityKeyIdentifier.from_public_key(self.private_key.public_key())
                    else:
                        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuing_ca.get_certificate().public_key())
                    builder = builder.add_extension(aki, critical=self.template["extensions"]["authorityKeyIdentifier"]["critical"])

            # Subject Key Identifier (SKI)
            if "subjectKeyIdentifier" in self.template["extensions"]:
                ski = x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key())
                builder = builder.add_extension(ski, critical=False)

            # ** Add Authority Key Identifier (AKI) **

        return builder


    def generate_certificate_from_template(
        self,
        issuing_ca: CertificationAuthority = None, 
        validity_days: int = 365
    ) -> bytes:
        """
        Generate a certificate based on the provided public key, signing private key, template, and request data.
        :param private_key_pem: Private key in PEM format

        :return: CSR in PEM format
        """

        subject = self.get_subject()

        # Set notValidBefore and notValidAfter
        not_valid_before = datetime.now(timezone.utc)
        max_validity = self.template["max_validity"]
        if max_validity > -1:
            if (validity_days > max_validity) or (validity_days == -1):
                validity_days = max_validity
        if validity_days > -1:
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
        else:
            not_valid_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # GeneralizedTime format

        if issuing_ca is None:
            signing_private_key = self.private_key
            issuer = subject 
            serial_number = x509.random_serial_number()
        else:
            signing_private_key = issuing_ca.get_private_key()
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
            .public_key(self.public_key)
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )

        cert_builder = self.add_template_extensions(cert_builder, issuing_ca=issuing_ca)

        # Add Request Extensions
        if "extensions" in self.template:
            # Subject Alternative Name (SAN) NOT CORRECT!!!
            if "subjectAltName" in self.request:
                alt_names = self.get_san()
                if alt_names:
                    cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=self.template["extensions"]["subjectAltName"]["critical"])

        # ✅ Sign the certificate
        certificate = cert_builder.sign(signing_private_key, hashes.SHA256())

        return certificate.public_bytes(serialization.Encoding.PEM)


    def generate_csr(self) -> bytes:
        """
        Generate a CSR based on the object's private key, template, and request data.
        :return: CSR in PEM format
        """

        subject = self.get_subject()

        # Build CSR with Subject
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        csr_builder = self.add_template_extensions(csr_builder)

        # Add Request Extensions
        if "extensions" in self.template:
            # Subject Alternative Name (SAN)
            if "subjectAltName" in self.request:
                alt_names = self.get_san()
                if alt_names:
                    csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=self.template["extensions"]["subjectAltName"]["critical"])

        # ✅ Sign CSR
        csr = csr_builder.sign(self.private_key, hashes.SHA256())

        return csr.public_bytes(serialization.Encoding.PEM)


    def generate_certificate_from_csr(
        self, 
        csr_pem: bytes,
        issuing_ca: CertificationAuthority = None, 
        validity_days: int = 365
    ) -> bytes:

        """
        Generate a certificate signed by a CA or self-signed.
        :param private_key_pem: Private key in PEM format
        :param csr_pem: CSR in PEM format
        :param validity_days: Number of days the certificate is valid for
        :return: Signed certificate in PEM format
        """
        csr = x509.load_pem_x509_csr(csr_pem)

        subject = csr.subject

        # Set notValidBefore and notValidAfter
        not_valid_before = datetime.now(timezone.utc)
        max_validity = self.template["max_validity"]
        if max_validity > -1:
            if (validity_days > max_validity) or (validity_days == -1):
                validity_days = max_validity
        if validity_days > -1:
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
        else:
            not_valid_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # GeneralizedTime format

        if issuing_ca is None:
            signing_private_key = self.private_key
            issuer = subject 
            serial_number = x509.random_serial_number()
        else:
            signing_private_key = issuing_ca.get_private_key()
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

        # ✅ Sign the certificate
        certificate = cert_builder.sign(signing_private_key, hashes.SHA256())

        return certificate.public_bytes(serialization.Encoding.PEM)

