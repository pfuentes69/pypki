import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timedelta, timezone

class PKIUtils:
    def __init__(self):
        """Initialize the PKI Utilities class."""
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

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def generate_csr(self, private_key_pem: bytes, template_json: str, request_json: str) -> bytes:
        """
        Generate a CSR based on the provided private key, template, and request data.
        :param private_key_pem: Private key in PEM format
        :param template_json: Certificate template JSON (dict format)
        :param request_json: Certificate request JSON (dict format)
        :return: CSR in PEM format
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        template = json.loads(template_json)
        request = json.loads(request_json)

        # ✅ Fixed OID Mapping for Subject Fields
        oid_mapping = {
            "commonName": x509.NameOID.COMMON_NAME,
            "organizationName": x509.NameOID.ORGANIZATION_NAME,
            "organizationalUnitName": x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
            "countryName": x509.NameOID.COUNTRY_NAME,
            "stateOrProvinceName": x509.NameOID.STATE_OR_PROVINCE_NAME,
            "localityName": x509.NameOID.LOCALITY_NAME,
        }

        # ✅ Ensure subject fields are set correctly
        subject_attrs = []
        for field, details in template["subject_name"]["fields"].items():
            value = request["subject_name"].get(field, details.get("default", ""))
            if details.get("mandatory", False) and not value:
                raise ValueError(f"Missing mandatory field: {field}")
            if value:
                subject_attrs.append(x509.NameAttribute(oid_mapping[field], value))

        subject = x509.Name(subject_attrs)

        # ✅ Build CSR with Subject
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        # ✅ Add Extensions
        if "extensions" in template:
            # Subject Alternative Name (SAN)
            if "subjectAltName" in request:
                alt_names = []
                if "dnsNames" in request["subjectAltName"]:
                    alt_names.extend([x509.DNSName(name) for name in request["subjectAltName"]["dnsNames"]])
                if "ipAddresses" in request["subjectAltName"]:
                    alt_names.extend([x509.IPAddress(name) for name in request["subjectAltName"]["ipAddresses"]])

                if alt_names:
                    csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)

            # Key Usage
            if "keyUsage" in template["extensions"]:
                key_usage_values = template["extensions"]["keyUsage"]["values"]
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
                csr_builder = csr_builder.add_extension(key_usage, critical=True)

            # "basicConstraints": { "critical": true, "ca": false, "pathLen": null },
            if "basicConstraints" in template["extensions"]:
                # Extract the basicConstraints field
                basic_constraints = template["extensions"]["basicConstraints"]
                
                # Get values
                critical = basic_constraints.get("critical", False)
                ca = basic_constraints.get("ca", False)
                path_len = basic_constraints.get("pathLen", None)
                
                # Convert pathLen null to Python None explicitly
                # path_length = "None" if path_len is None else path_len
                # csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca, path_len), critical)

            if "policyIdentifiers" in template["extensions"]:
                policy_information = []
                for policy_oid in template["extensions"]["policyIdentifiers"]:
                    # Create PolicyInformation objects for each policy
                    policy_information.append(x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), []))

                policy = x509.CertificatePolicies(policy_information)
                csr_builder = csr_builder.add_extension(policy, critical=False)
            
            # 2. Add AIA (Authority Information Access)
            # AIA extension can include OCSP URI and/or CA Issuers URI
            if "aia" in template["extensions"]:
                aia_list =[]
                if "OCSP" in template["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.1'), x509.UniformResourceIdentifier(template["extensions"]["aia"]["authorityInfoAccess"]["OCSP"]["url"])))
                if "caIssuers" in template["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.2'), x509.UniformResourceIdentifier(template["extensions"]["aia"]["authorityInfoAccess"]["caIssuers"]["url"])))

                aia = x509.AuthorityInformationAccess(aia_list)
                csr_builder = csr_builder.add_extension(aia, critical=False)

            # 3. Add CDP (Certificate Distribution Points)
            if "cdp" in template["extensions"]:
                cdp_uri = template["extensions"]["cdp"]["url"]
                critical = template["extensions"]["cdp"]["critical"]
                cdp = x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ])
                csr_builder = csr_builder.add_extension(cdp, critical=False)

            # Extended Key Usage
            if "extendedKeyUsage" in template["extensions"]:
                eku_values = template["extensions"]["extendedKeyUsage"]["allowed"]
                eku_oids = {
                    "serverAuth": x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    "clientAuth": x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    "emailProtection": x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    "codeSigning": x509.ExtendedKeyUsageOID.CODE_SIGNING,
                    "timeStamping": x509.ExtendedKeyUsageOID.TIME_STAMPING,
                }
                eku_list = [eku_oids[usage] for usage in eku_values if usage in eku_oids]
                if eku_list:
                    csr_builder = csr_builder.add_extension(x509.ExtendedKeyUsage(eku_list), critical=False)

        # ✅ Sign CSR
        csr = csr_builder.sign(private_key, hashes.SHA256())

        return csr.public_bytes(serialization.Encoding.PEM)

    def generate_certificate_from_csr(
        self, private_key_pem: bytes, csr_pem: bytes, template_json: str, ca_cert_pem: bytes = None, validity_days: int = 365
    ) -> bytes:
        """
        Generate a certificate signed by a CA or self-signed.
        :param private_key_pem: Private key in PEM format
        :param csr_pem: CSR in PEM format
        :param ca_cert_pem: CA certificate in PEM format (None for self-signed)
        :param validity_days: Number of days the certificate is valid for
        :return: Signed certificate in PEM format
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        csr = x509.load_pem_x509_csr(csr_pem)

        template = json.loads(template_json)

        subject = csr.subject
        issuer = subject if ca_cert_pem is None else x509.load_pem_x509_certificate(ca_cert_pem).subject
        serial_number = x509.random_serial_number()

        # Set notValidBefore and notValidAfter
        not_valid_before = datetime.utcnow()
        max_validity = template["max_validity"]
        if max_validity > -1:
            if (validity_days > max_validity) or (validity_days == -1):
                validity_days = max_validity
        if validity_days > -1:
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
        else:
            not_valid_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # GeneralizedTime format
        # Check if the validity surpasses the CA
        if ca_cert_pem is not None:
            ca_validity = x509.load_pem_x509_certificate(ca_cert_pem).not_valid_after_utc
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
        certificate = cert_builder.sign(private_key, hashes.SHA256())

        return certificate.public_bytes(serialization.Encoding.PEM)

    def generate_certificate_from_template(self, public_key: bytes, private_key_pem: bytes, request_json: str, template_json: str, ca_cert_pem: bytes = None, validity_days: int = 365) -> bytes:
        """
        Generate a certificate based on the provided public key, signing private key, template, and request data.
        :param private_key_pem: Private key in PEM format
        :param template_json: Certificate template JSON (dict format)
        :param request_json: Certificate request JSON (dict format)
        :return: CSR in PEM format
        """
        # public_key = serialization.load_pem_public_key(public_key_pem)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        template = json.loads(template_json)
        request = json.loads(request_json)

        # ✅ Fixed OID Mapping for Subject Fields
        oid_mapping = {
            "commonName": x509.NameOID.COMMON_NAME,
            "organizationName": x509.NameOID.ORGANIZATION_NAME,
            "organizationalUnitName": x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
            "countryName": x509.NameOID.COUNTRY_NAME,
            "stateOrProvinceName": x509.NameOID.STATE_OR_PROVINCE_NAME,
            "localityName": x509.NameOID.LOCALITY_NAME,
        }

        # ✅ Ensure subject fields are set correctly
        subject_attrs = []
        for field, details in template["subject_name"]["fields"].items():
            value = request["subject_name"].get(field, details.get("default", ""))
            if details.get("mandatory", False) and not value:
                raise ValueError(f"Missing mandatory field: {field}")
            if value:
                subject_attrs.append(x509.NameAttribute(oid_mapping[field], value))

        subject = x509.Name(subject_attrs)
        issuer = subject if ca_cert_pem is None else x509.load_pem_x509_certificate(ca_cert_pem).subject
        serial_number = x509.random_serial_number()

        # Set notValidBefore and notValidAfter
        not_valid_before = datetime.utcnow()
        max_validity = template["max_validity"]
        if max_validity > -1:
            if (validity_days > max_validity) or (validity_days == -1):
                validity_days = max_validity
        if validity_days > -1:
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
        else:
            not_valid_after = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)  # GeneralizedTime format
        # Check if the validity surpasses the CA
        if ca_cert_pem is not None:
            ca_validity = x509.load_pem_x509_certificate(ca_cert_pem).not_valid_after_utc
            if not_valid_after > ca_validity:
                not_valid_after = ca_validity

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )

        # ✅ Add Extensions
        if "extensions" in template:
            # Subject Alternative Name (SAN) NOT CORRECT!!!
            if "subjectAltName" in request:
                alt_names = []
                if "dnsNames" in request["subjectAltName"]:
                    alt_names.extend([x509.DNSName(name) for name in request["subjectAltName"]["dnsNames"]])
                if "ipAddresses" in request["subjectAltName"]:
                    alt_names.extend([x509.IPAddress(name) for name in request["subjectAltName"]["ipAddresses"]])

                if alt_names:
                    cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)

            # Key Usage
            if "keyUsage" in template["extensions"]:
                key_usage_values = template["extensions"]["keyUsage"]["values"]
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
                cert_builder = cert_builder.add_extension(key_usage, critical=True)

            # "basicConstraints": { "critical": true, "ca": false, "pathLen": null },
            if "basicConstraints" in template["extensions"]:
                # Extract the basicConstraints field
                basic_constraints = template["extensions"]["basicConstraints"]
                
                # Get values
                critical = basic_constraints.get("critical", False)
                ca = basic_constraints.get("ca", False)
                path_len = basic_constraints.get("pathLen", None)
                
                # Convert pathLen null to Python None explicitly
                # path_length = "None" if path_len is None else path_len
                # csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca, path_len), critical)

            if "policyIdentifiers" in template["extensions"]:
                policy_information = []
                for policy_oid in template["extensions"]["policyIdentifiers"]:
                    # Create PolicyInformation objects for each policy
                    policy_information.append(x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), []))

                policy = x509.CertificatePolicies(policy_information)
                cert_builder = cert_builder.add_extension(policy, critical=False)
            
            # 2. Add AIA (Authority Information Access)
            # AIA extension can include OCSP URI and/or CA Issuers URI
            if "aia" in template["extensions"]:
                aia_list =[]
                if "OCSP" in template["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.1'), x509.UniformResourceIdentifier(template["extensions"]["aia"]["authorityInfoAccess"]["OCSP"]["url"])))
                if "caIssuers" in template["extensions"]["aia"]["authorityInfoAccess"]:
                    aia_list.append(x509.AccessDescription(x509.ObjectIdentifier('1.3.6.1.5.5.7.48.2'), x509.UniformResourceIdentifier(template["extensions"]["aia"]["authorityInfoAccess"]["caIssuers"]["url"])))

                aia = x509.AuthorityInformationAccess(aia_list)
                cert_builder = cert_builder.add_extension(aia, critical=False)

            # 3. Add CDP (Certificate Distribution Points)
            if "cdp" in template["extensions"]:
                cdp_uri = template["extensions"]["cdp"]["url"]
                critical = template["extensions"]["cdp"]["critical"]
                cdp = x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ])
                cert_builder = cert_builder.add_extension(cdp, critical=False)

            # Extended Key Usage
            if "extendedKeyUsage" in template["extensions"]:
                eku_values = template["extensions"]["extendedKeyUsage"]["allowed"]
                eku_oids = {
                    "serverAuth": x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    "clientAuth": x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    "emailProtection": x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    "codeSigning": x509.ExtendedKeyUsageOID.CODE_SIGNING,
                    "timeStamping": x509.ExtendedKeyUsageOID.TIME_STAMPING,
                }
                eku_list = [eku_oids[usage] for usage in eku_values if usage in eku_oids]
                if eku_list:
                    cert_builder = cert_builder.add_extension(x509.ExtendedKeyUsage(eku_list), critical=False)

        # ✅ Sign the certificate
        certificate = cert_builder.sign(private_key, hashes.SHA256())

        return certificate.public_bytes(serialization.Encoding.PEM)
