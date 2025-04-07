import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from asn1crypto import x509 as asn1_x509
from asn1crypto.core import OctetBitString
from ipaddress import ip_address
from datetime import datetime, timedelta, timezone
from pypki.ca import CertificationAuthority
from pypki.pki_tools import PKITools
from pypki.key_tools import KeyTools


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
        Add extensions based in the loaded template and Issuing CA
        """
        if issuing_ca is not None:
            # The extensions in the CA config must be processed
            # We only check for CDP and AIA for now
            if "extensions" in issuing_ca.get_config():
                print("The CA has extensions")

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