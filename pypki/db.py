import json
import threading
from contextlib import contextmanager
import mysql.connector
import mysql.connector.pooling
from mysql.connector import OperationalError, IntegrityError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime
from werkzeug.security import generate_password_hash
from .ca import CertificationAuthority
from .ocsp_responder import OCSPResponder
from .log import logger


class DuplicateSerialError(Exception):
    """Raised when a generated serial number collides with an existing one for the same CA."""


class PKIDataBase:
    # Default pool size. Override via db_config key "pool_size" if needed.
    _DEFAULT_POOL_SIZE = 5

    def __init__(self, config_json = None):
        """Initialize the PKI Database class."""
        self.__config = {}
        self._pool = None           # MySQLConnectionPool; created lazily on first use
        self._local = threading.local()  # thread-local storage for the active connection
        if config_json:
            self.load_config(config_json)


    # Load database configuration from JSON dict
    def load_config(self, config):
        self.__config = config


    # Load database configuration from JSON file
    def load_config_json(self, config_json:str):
        self.__config = json.loads(config_json)


    def connect_to_db(self):
        """Create the connection pool if it does not exist yet (idempotent)."""
        if self._pool is not None:
            return
        try:
            pool_size = self.__config.get("pool_size", self._DEFAULT_POOL_SIZE)
            self._pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="pypki",
                pool_size=pool_size,
                pool_reset_session=True,
                host=self.__config["host"],
                port=self.__config["port"],
                user=self.__config["user"],
                password=self.__config["password"],
            )
            logger.info(f"DB connection pool created (size={pool_size})")
        except mysql.connector.Error as e:
            logger.error(f"Error creating connection pool: {e}")
            raise


    def close_db(self):
        """Return the thread-local connection to the pool (no-op if none checked out)."""
        conn = getattr(self._local, 'connection', None)
        if conn is not None:
            try:
                conn.close()   # returns to pool; does not close the underlying socket
            except Exception:
                pass
            self._local.connection = None


    def get_connection(self):
        """Return the connection currently checked out for this thread, or None."""
        return getattr(self._local, 'connection', None)


    @contextmanager
    def connection(self):
        """Check out a connection from the pool for the duration of the block.

        The connection is stored in thread-local storage so all DB methods called
        within the same block share the same connection and transaction context.
        The connection is automatically returned to the pool when the block exits.
        """
        self.connect_to_db()
        conn = self._pool.get_connection()
        self._local.connection = conn
        try:
            yield self
        finally:
            try:
                conn.close()   # returns to pool
            except Exception:
                pass
            self._local.connection = None

    def get_key_record(self, key_id: int):
        """
        Retrieve a row from KeyStorage by ID.
        Returns a dict or None if not found.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT * FROM KeyStorage WHERE id = %s", (key_id,))
            result = cursor.fetchone()
            cursor.close()
            return result if result else None
        except mysql.connector.Error as err:
            logger.error(f"Error retrieving KeyStorage record: {err}")
            return None


    def insert_key(self, private_key: str, storage_type: str = "Plain",
                   public_key: str = None, key_type: str = None,
                   hsm_slot: int = None, hsm_token_id: str = None,
                   token_password: str = None) -> int:
        """
        Insert a row into KeyStorage.
        Returns the new row id.

        For software keys only private_key, storage_type, public_key, and
        key_type are used.  For HSM keys also pass hsm_slot, hsm_token_id,
        and token_password.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "INSERT INTO KeyStorage "
                "(private_key, storage_type, public_key, key_type, "
                " hsm_slot, hsm_token_id, token_password) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (private_key, storage_type, public_key, key_type,
                 hsm_slot, hsm_token_id, token_password)
            )
            self._local.connection.commit()
            new_id = cursor.lastrowid
            cursor.close()
            logger.info(f"Inserted KeyStorage id={new_id}")
            return new_id
        except mysql.connector.Error as err:
            logger.error(f"Error inserting KeyStorage record: {err}")
            return None


    def insert_ca(self, ca: CertificationAuthority):
        """
        Insert a Certification Authority into the database.
        The private key (if software-based) is stored in KeyStorage and
        referenced via private_key_reference.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            # Load cert, calculate SKI, and derive key metadata
            cert = x509.load_pem_x509_certificate(ca.get_config()["crypto"]["certificate"].encode("utf-8"))
            public_key = cert.public_key()

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                digest = hashes.Hash(hashes.SHA1())
                digest.update(public_bytes)
                ski = digest.finalize().hex()
                key_type = f"ECDSA-{public_key.curve.name}"
            else:
                spki_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                digest = hashes.Hash(hashes.SHA1())
                digest.update(spki_der)
                ski = digest.finalize().hex()
                key_type = f"RSA-{public_key.key_size}"

            # Insert private key into KeyStorage; store the returned id as
            # private_key_reference so the KMS can load it at runtime.
            private_key_reference = None
            private_key_pem = ca.get_config()["crypto"].get("private_key")
            if private_key_pem:
                pub_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
                cursor.execute(
                    "INSERT INTO KeyStorage (private_key, storage_type, public_key, key_type) VALUES (%s, %s, %s, %s)",
                    (private_key_pem, "Plain", pub_key_pem, key_type)
                )
                private_key_reference = cursor.lastrowid
                logger.info(f"CA private key stored in KeyStorage id={private_key_reference}")

            insert_query = """
                INSERT INTO CertificationAuthorities (
                    name, certificate, ski, private_key_reference, certificate_chain,
                    max_validity, serial_number_length,
                    crl_validity, extensions
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            data = (
                ca.get_config()["ca_name"],
                ca.get_config()["crypto"]["certificate"],
                ski,
                private_key_reference,
                ca.get_config()["crypto"]["certificate_chain"],
                ca.get_config()["max_validity"],
                ca.get_config()["serial_number_length"],
                ca.get_config()["crl_validity"],
                json.dumps(ca.get_config()["extensions"])
            )

            cursor.execute(insert_query, data)
            self._local.connection.commit()
            logger.info("Certification Authority inserted successfully!")

        except mysql.connector.Error as err:
            logger.error(f"Error inserting Certification Authority: {err}")
        finally:
            cursor.close()


    def get_ca_id_by_name(self, ca_name: str):
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT id FROM CertificationAuthorities WHERE name = %s
            """
            cursor.execute(query, (ca_name,))
            result = cursor.fetchone()
            cursor.close()
        
            return result[0] if result else None
        except mysql.connector.Error as err:
            logger.error(err)
            return None

    def get_ca_id_by_ski(self, ca_ski: str):
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT id FROM CertificationAuthorities WHERE ski = %s
            """
            cursor.execute(query, (ca_ski,))
            result = cursor.fetchone()
            cursor.close()
        
            return result[0] if result else None
        except mysql.connector.Error as err:
            logger.error(err)
            return None


    def get_ca_record_by_id(self, ca_id: int):
        """
        Retrieves the record corresponding to a given 'ca_id' in the CertificationAuthorities table.
        
        :param db_connection: Active MySQL database connection
        :param ca_id: The ID of the Certification Authority to retrieve
        :return: The record as a dictionary if found, else None
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT * FROM CertificationAuthorities WHERE id = %s
            """
            cursor.execute(query, (ca_id,))
            result = cursor.fetchone()
            cursor.close()
            
            return result if result else None
        except mysql.connector.Error as err:
            logger.error(f"Error: {err}")
            return None

    def update_ca(self, ca_id: int, fields: dict):
        """
        Update editable fields of a CertificationAuthority row.

        Allowed keys in `fields`: name, max_validity, serial_number_length,
        crl_validity, extensions (must already be a JSON string).

        Returns True on success, False otherwise.
        """
        ALLOWED = {"name", "max_validity", "serial_number_length", "crl_validity", "extensions"}
        updates = {k: v for k, v in fields.items() if k in ALLOWED}
        if not updates:
            return False
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            set_clause = ", ".join(f"{col} = %s" for col in updates)
            values = list(updates.values()) + [ca_id]
            cursor.execute(
                f"UPDATE CertificationAuthorities SET {set_clause} WHERE id = %s",
                values
            )
            self._local.connection.commit()
            affected = cursor.rowcount
            cursor.close()
            return affected > 0
        except mysql.connector.Error as err:
            logger.error(f"Error updating CA: {err}")
            return False

    def get_ca_collection(self):
        """
        Retrieves a collection of CA IDs and names from the CertificationAuthorities table.
        
        :param db_config: Dictionary containing database connection parameters.
        :return: List of dictionaries with 'id' and 'name'.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")

            query = "SELECT * FROM CertificationAuthorities"
            cursor.execute(query)
            ca_collection = cursor.fetchall()  # Fetch all results

            return ca_collection

        except mysql.connector.Error as e:
            logger.error(f"Database error: {e}")
            return []

        finally:
            if 'cursor' in locals():
                cursor.close()


    def insert_ocsp_responder(self, ocsp_resp: OCSPResponder):
        """
        Insert an OCSP Responder into the database.
        The private key (if software-based) is stored in KeyStorage and
        referenced via private_key_reference.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            # Insert private key into KeyStorage
            private_key_reference = None
            private_key_pem = ocsp_resp.get_config()["crypto"].get("private_key")
            if private_key_pem:
                cert_pem = ocsp_resp.get_config()["crypto"].get("certificate")
                pub_key_pem = None
                key_type = None
                if cert_pem:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
                    public_key = cert.public_key()
                    pub_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
                    if isinstance(public_key, ec.EllipticCurvePublicKey):
                        key_type = f"ECDSA-{public_key.curve.name}"
                    else:
                        key_type = f"RSA-{public_key.key_size}"
                cursor.execute(
                    "INSERT INTO KeyStorage (private_key, storage_type, public_key, key_type) VALUES (%s, %s, %s, %s)",
                    (private_key_pem, "Plain", pub_key_pem, key_type)
                )
                private_key_reference = cursor.lastrowid
                logger.info(f"OCSP responder private key stored in KeyStorage id={private_key_reference}")

            insert_query = """
                INSERT INTO OCSPResponders (
                    name, issuer_ski, issuer_certificate,
                    private_key_reference, certificate, response_validity
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """

            data = (
                ocsp_resp.get_config()["name"],
                ocsp_resp.get_config()["issuer_ski"],
                ocsp_resp.get_config()["issuer_certificate"],
                private_key_reference,
                ocsp_resp.get_config()["crypto"]["certificate"],
                ocsp_resp.get_config()["response_validity"]
            )

            cursor.execute(insert_query, data)
            self._local.connection.commit()
            logger.info("OCSP Responder inserted successfully!")

        except mysql.connector.Error as err:
            logger.error(f"Error inserting OCSP Responder: {err}")
        finally:
            cursor.close()


    def get_ocsp_responders_collection(self):
        """
        Retrieves a collection of OCSP Responders from the OCSPResponders table.
        
        :return: List of objects
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")

            query = "SELECT * FROM OCSPResponders"
            cursor.execute(query)

            # Build the list of OCSPResponder objects
            ocsp_responders = []
            for row in cursor.fetchall():
                responder = OCSPResponder(
                    name=row['name'],
                    issuer_ski=row['issuer_ski'],
                    issuer_certificate=row['issuer_certificate'],
                    response_validity=row['response_validity'],
                    certificate_pem=row['certificate'],
                    kms_key_id=row.get('private_key_reference')
                )
                ocsp_responders.append(responder)

            return ocsp_responders

        except mysql.connector.Error as e:
            logger.error(f"Database error: {e}")
            return []

        finally:
            if 'cursor' in locals():
                cursor.close()


    def get_template_collection(self):
        """
        Retrieves a collection of Cetificate Templates from the CertificateTemplates table.
        
        :return: List of objects
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")

            query = "SELECT * FROM CertificateTemplates"
            cursor.execute(query)
            template_collection = cursor.fetchall()  # Fetch all results

            return template_collection
        except mysql.connector.Error as e:
            logger.error(f"Database error: {e}")
            return []

        finally:
            if 'cursor' in locals():
                cursor.close()


    def insert_cert_template(self, cert_template: dict):
        """
        Method to insert a Certificate Template object into the database.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            
            insert_query = """
                INSERT INTO CertificateTemplates (
                    name, definition
                ) VALUES (%s, %s)
            """
            data = (
                cert_template["template_name"],
                json.dumps(cert_template)
            )

            cursor.execute(insert_query, data)
            self._local.connection.commit()
            logger.info("Certificate Template inserted successfully!")

            new_id = cursor.lastrowid
            return new_id

        except mysql.connector.Error as err:
            logger.error(f"Error inserting Certificate Template: {err}")
            return None
        finally:
            cursor.close()


    def update_cert_template(self, template_id: int, cert_template: dict):
        """Update an existing Certificate Template."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            update_query = """
                UPDATE CertificateTemplates
                SET name = %s, definition = %s
                WHERE id = %s
            """
            data = (
                cert_template["template_name"],
                json.dumps(cert_template),
                template_id
            )

            cursor.execute(update_query, data)
            self._local.connection.commit()
            return cursor.rowcount > 0

        except mysql.connector.Error as err:
            logger.error(f"Error updating Certificate Template: {err}")
            return False
        finally:
            cursor.close()


    def get_cert_template_id_by_name(self, cert_template_name: str):
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT id FROM CertificateTemplates WHERE name = %s
            """
            cursor.execute(query, (cert_template_name,))
            result = cursor.fetchone()
            cursor.close()
        
            return result[0] if result else None
        except mysql.connector.Error as err:
            logger.error(f"Error: {err}")
            return None


    def get_cert_template_record_by_id(self, cert_template_id: int):
        """
        Retrieves the record corresponding to a given 'cert_template_id' in the CertificateTemplates table.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT * FROM CertificateTemplates WHERE id = %s
            """
            cursor.execute(query, (cert_template_id,))
            result = cursor.fetchone()
            cursor.close()
            
            return result if result else None

        except mysql.connector.Error as err:
            logger.error(f"Error: {err}")
            return None
        

    def export_cert_template(self, cert_template_id: int):
        """
        Returns the definition of a Certificate Template as a dict, suitable for export.
        """
        record = self.get_cert_template_record_by_id(cert_template_id)
        if not record:
            return None
        definition = record.get("definition")
        if isinstance(definition, str):
            return json.loads(definition)
        return definition


    def get_ca_and_template_id_by_alias_name(self, alias_name = None):
        """
        Retrieve EST alias config (ca_id, template_id, username, password_hash)
        by alias name, or the default alias when no name is provided.

        Args:
            alias_name (str): The alias name to look up. If None, returns the
                              alias with is_default = TRUE.

        Returns:
            dict or None: Row with ca_id, template_id, username, password_hash;
                          or None if not found.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            if alias_name:
                query = """
                    SELECT ca_id, template_id, username, password_hash
                    FROM ESTAliases
                    WHERE name = %s
                """
                cursor.execute(query, (alias_name,))
            else:
                query = """
                    SELECT ca_id, template_id, username, password_hash
                    FROM ESTAliases
                    WHERE is_default = TRUE LIMIT 1;
                """
                cursor.execute(query)

            result = cursor.fetchone()
            cursor.close()

            return result if result else None

        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None


    def insert_certificate(self, pem_certificate: bytes, ca_id: int, template_id: int, private_key_reference: int = None):
        """
        Inserts a certificate record into the Certificates table.
        
        :param pem_certificate: Certificate in PEM format (string)
        :param ca_id: The CA ID related to this certificate
        :param type_id: The certificate type ID
        :param private_key_reference: (Optional) Reference to the private key ID
        """
        try:
            # Parse the PEM certificate
            cert = x509.load_pem_x509_certificate(pem_certificate, default_backend())
            
            # Extract certificate details
            serial_number = format(cert.serial_number, 'x')
            subject_name = cert.subject.rfc4514_string()
            issuer_name = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            public_key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            
            # Convert datetime to string format compatible with MySQL
            not_before_str = not_before.strftime('%Y-%m-%d %H:%M:%S')
            not_after_str = not_after.strftime('%Y-%m-%d %H:%M:%S')

            # Establish database connection
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            # Insert query
            insert_query = """
                INSERT INTO Certificates (
                    ca_id, template_id, serial_number, subject_name, issuer_name,
                    not_before, not_after, public_key, private_key_reference, certificate_data, fingerprint
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            data = (
                ca_id,
                template_id,
                str(serial_number),
                subject_name,
                issuer_name,
                not_before_str,
                not_after_str,
                public_key,
                private_key_reference,
                pem_certificate,
                fingerprint
            )

            # Execute and commit
            cursor.execute(insert_query, data)
            # Get the generated ID
            new_id = cursor.lastrowid
            # Commit the transaction
            self._local.connection.commit()
            logger.info(f"Certificate inserted successfully! New ID: {new_id}")

        except IntegrityError as err:
            if err.errno == 1062 and 'uq_ca_serial' in str(err):
                raise DuplicateSerialError(
                    f"Serial number collision for ca_id={ca_id}: {serial_number}"
                ) from err
            logger.error(f"Database integrity error: {err}")
            return None
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None
        except Exception as e:
            logger.error(f"Problem processing certificate: {e}")
        finally:
            cursor.close()

        return new_id

    def get_certificate_list(self, ca_id, template_id, page, per_page, offset,
                              status=None, expiring_soon=False):
        try:
            base_where = "WHERE 1=1"
            params = []

            if ca_id is not None:
                base_where += " AND ca_id = %s"
                params.append(ca_id)

            if template_id is not None:
                base_where += " AND template_id = %s"
                params.append(template_id)

            if expiring_soon:
                base_where += (
                    " AND status = 'Active'"
                    " AND not_after BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAY)"
                )
            elif status is not None:
                base_where += " AND status = %s"
                params.append(status)

            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True, dictionary=True)
            cursor.execute(f"USE {db_name}")

            query = (
                "SELECT id, ca_id, template_id, serial_number, subject_name,"
                " not_before, not_after, status"
                f" FROM Certificates {base_where}"
                " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            )
            cursor.execute(query, params + [per_page, offset])
            results = cursor.fetchall()

            cursor.execute(f"SELECT COUNT(*) FROM Certificates {base_where}", params)
            total = cursor.fetchone()['COUNT(*)']

        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None
        except Exception as e:
            logger.error(f"Problem processing certificate: {e}")
        finally:
            cursor.close()

        return total, results


    def get_certificate_id(self, serial_number=None, ca_id=None, fingerprint=None):
        """
        Retrieve the certificate ID from the database based on the given criteria.

        Parameters:
            db_connection: Active MySQL database connection.
            serial_number (str, optional): The certificate serial number.
            ca_id (int, optional): The Certificate Authority ID (required if searching by serial_number).
            fingerprint (str, optional): The unique fingerprint of the certificate.

        Returns:
            int: Certificate ID if found, otherwise None.
        """

        query = "SELECT id FROM Certificates WHERE "
        params = []

        if serial_number is not None and ca_id is not None:
            query += "serial_number = %s AND ca_id = %s"
            params.extend([serial_number, ca_id])
        elif fingerprint is not None:
            query += "fingerprint = %s"
            params.append(fingerprint)
        else:
            raise ValueError("At least one valid search criteria must be provided.")

        db_name = self.__config["database"]
        cursor = self._local.connection.cursor(buffered=True)
        cursor.execute(f"USE {db_name}")
        cursor.execute(query, params)
        result = cursor.fetchone()  # Fetch one matching record
        cursor.close()

        return result[0] if result else None  # Return ID or None if not found


    def get_certificate_record(self, certificate_id=None, serial_number=None, ca_id=None, fingerprint=None):
        """
        Retrieve a certificate record from the database based on the given criteria.

        Parameters:
            db_connection: Active MySQL database connection.
            certificate_id (int, optional): The unique certificate ID.
            serial_number (str, optional): The certificate serial number.
            ca_id (int, optional): The Certificate Authority ID (required if searching by serial_number).
            fingerprint (str, optional): The unique fingerprint of the certificate.

        Returns:
            dict: Certificate record if found, otherwise None.
        """

        query = "SELECT * FROM Certificates WHERE "
        params = []

        if certificate_id is not None:
            query += "id = %s"
            params.append(certificate_id)
        elif serial_number is not None and ca_id is not None:
            query += "serial_number = %s AND ca_id = %s"
            params.extend([serial_number, ca_id])
        elif fingerprint is not None:
            query += "fingerprint = %s"
            params.append(fingerprint)
        else:
            raise ValueError("At least one valid search criteria must be provided.")
        
        # Establish database connection
        db_name = self.__config["database"]
        cursor = self._local.connection.cursor(buffered=True, dictionary=True)
        cursor.execute(f"USE {db_name}")
        cursor.execute(query, params)
        result = cursor.fetchone()  # Retrieve one matching record
        cursor.close()

        return result  # Returns a dictionary or None if not found


    def get_certificate_status(self, certificate_id=None, serial_number=None, ca_id=None, fingerprint=None):
        """
        Retrieve certificate status including serial number, fingerprint, revocation status, and revocation time.

        Parameters:
            certificate_id (int, optional): Unique certificate ID.
            serial_number (str, optional): Certificate serial number.
            ca_id (int, optional): Certificate Authority ID (required if searching by serial_number).
            fingerprint (str, optional): Certificate fingerprint.

        Returns:
            tuple: (serial_number, fingerprint, status, revocation_time)
                or None if certificate not found.
        """
        # Query for certificate record
        cert = self.get_certificate_record(
            certificate_id=certificate_id,
            serial_number=serial_number,
            ca_id=ca_id,
            fingerprint=fingerprint
        )

        if not cert:
            return None  # Not found

        serial = cert.get("serial_number")
        fp = cert.get("fingerprint")
        revoked = cert.get("status")  # Expected to be boolean or similar
        revocation_time = cert.get("revoked_at")  # Could be None or datetime
        revocation_reason = cert.get("revocation_reason")  # Could be None or int
        cert_pem = cert.get("certificate_data")

        """
        # Determine status
        if revoked :
            status = "Revoked"
        elif revoked is False:
            status = "Good"
        else:
            status = "Unknown"
        """
            
        return (serial, fp, revoked, revocation_time, revocation_reason, cert_pem)


    def revoke_certificate(self, certificate_id, revocation_reason):
        """
        Marks a certificate as revoked and sets the revocation reason and timestamp.

        Parameters:
            db_connection: Active MySQL database connection.
            certificate_id (int): The certificate ID to be revoked.
            revocation_reason (int): The revocation reason code to be stored.
            
        Returns:
            bool: True if the certificate was successfully updated, False otherwise.
        """

        # Get the current timestamp
        revoked_at = datetime.now()

        query = """
            UPDATE Certificates
            SET status = 'Revoked',
                revoked_at = %s,
                revocation_reason = %s
            WHERE id = %s AND status != 'Revoked'
        """

        params = (revoked_at, revocation_reason, certificate_id)

        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(query, params)
            self._local.connection.commit()  # Commit the changes to the database

            if cursor.rowcount > 0:  # Check if any row was affected (i.e., the certificate was updated)
                cursor.close()
                return True
            else:
                cursor.close()
                return False  # No certificate found or already revoked
        except mysql.connector.Error as err:
            logger.error(f"Error: {err}")
            return False


    def get_revoked_certificates(self, ca_id):
        """
        Fetches revoked certificates for a given CA from the database and builds a list of revoked certificates.

        Parameters:
            ca_id (int): The CA ID to search for revoked certificates.

        Returns:
            List[tuple]: A list of tuples containing (serial_number, revocation_time, reason_code) for each revoked certificate.
        """
        # Connect to the database
        db_name = self.__config["database"]
        cursor = self._local.connection.cursor(dictionary=True, buffered=True)
        cursor.execute(f"USE {db_name}")
        
        # SQL query to fetch revoked certificates for the given ca_id
        query = """
        SELECT serial_number, revoked_at, revocation_reason 
        FROM Certificates 
        WHERE ca_id = %s AND status = 'Revoked'
        """
        
        # Execute the query with the provided ca_id
        cursor.execute(query, (ca_id,))
        
        # Fetch the results
        rows = cursor.fetchall()
        
        revoked_certificates = []
        
        # Iterate over the rows and format the data
        for row in rows:
            serial_number = int(row['serial_number'], 16)
            revoked_at = row['revoked_at']
            revocation_reason = row['revocation_reason']
            
            # Ensure the revocation time is a datetime object
#            revoked_time = datetime.strptime(revoked_at, "%Y-%m-%d %H:%M:%S") if revoked_at else None
            
            # Add the certificate information to the revoked_certificates list
            revoked_certificates.append((serial_number, revoked_at, revocation_reason))
        
        # Close the cursor and the connection
        cursor.close()
        
        return revoked_certificates


    def get_dashboard_stats(self):
        """
        Returns certificate and CA counts for the dashboard in a single round-trip.

        Returns:
            dict with keys: active, revoked, expiring_soon, cas, ca_overview (list of dicts).
        """
        db_name = self.__config["database"]
        cursor = self._local.connection.cursor(dictionary=True, buffered=True)
        cursor.execute(f"USE {db_name}")

        cursor.execute("""
            SELECT
                SUM(status = 'Active')  AS active,
                SUM(status = 'Revoked') AS revoked,
                SUM(status = 'Active'
                    AND not_after BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAY)
                ) AS expiring_soon
            FROM Certificates
        """)
        cert_row = cursor.fetchone()

        cursor.execute("SELECT COUNT(*) AS cas FROM CertificationAuthorities")
        ca_row = cursor.fetchone()

        cursor.execute("""
            SELECT
                COUNT(*)                                                          AS total,
                SUM(certificate IS NULL OR certificate = '')                      AS no_cert,
                SUM(not_after IS NOT NULL AND not_after <= NOW())                 AS expired,
                SUM(not_after IS NOT NULL
                    AND not_after > NOW()
                    AND not_after <= DATE_ADD(NOW(), INTERVAL 30 DAY))            AS expiring_soon
            FROM OCSPResponders
        """)
        ocsp_row = cursor.fetchone()

        cursor.execute("""
            SELECT
                ca.id,
                ca.name,
                COUNT(c.id)          AS issued,
                SUM(c.status = 'Revoked') AS revoked
            FROM CertificationAuthorities ca
            LEFT JOIN Certificates c ON c.ca_id = ca.id
            GROUP BY ca.id, ca.name
            ORDER BY ca.name
        """)
        ca_overview = cursor.fetchall()
        cursor.close()

        ocsp_total        = int(ocsp_row["total"]        or 0)
        ocsp_no_cert      = int(ocsp_row["no_cert"]      or 0)
        ocsp_expired      = int(ocsp_row["expired"]      or 0)
        ocsp_expiring     = int(ocsp_row["expiring_soon"] or 0)
        if ocsp_total == 0:
            ocsp_status = "none"
        elif ocsp_no_cert + ocsp_expired + ocsp_expiring > 0:
            ocsp_status = "warn"
        else:
            ocsp_status = "ok"

        return {
            "active":        int(cert_row["active"]        or 0),
            "revoked":       int(cert_row["revoked"]       or 0),
            "expiring_soon": int(cert_row["expiring_soon"] or 0),
            "cas":           int(ca_row["cas"]             or 0),
            "ca_overview": [
                {
                    "id":      row["id"],
                    "name":    row["name"],
                    "issued":  int(row["issued"]  or 0),
                    "revoked": int(row["revoked"] or 0),
                }
                for row in ca_overview
            ],
            "ocsp": {
                "status":       ocsp_status,
                "total":        ocsp_total,
                "expired":      ocsp_expired,
                "expiring_soon": ocsp_expiring,
                "no_cert":      ocsp_no_cert,
            },
        }


    def get_crl(self, ca_id):
        """
        Retrieve the latest CRL record for a given CA.

        Parameters:
            ca_id (int): The CA ID.

        Returns:
            dict: CRL record (ca_id, crl_data, issue_date, next_update) or None.
        """
        db_name = self.__config["database"]
        cursor = self._local.connection.cursor(dictionary=True, buffered=True)
        cursor.execute(f"USE {db_name}")
        cursor.execute(
            "SELECT * FROM CertificateRevocationLists WHERE ca_id = %s",
            (ca_id,)
        )
        result = cursor.fetchone()
        cursor.close()
        return result


    def upsert_crl(self, ca_id, crl_pem: str, issue_date, next_update):
        """
        Insert or update the CRL for a given CA in CertificateRevocationLists,
        keeping only one row per CA (the latest CRL).

        Parameters:
            ca_id (int): The CA ID.
            crl_pem (str): PEM-encoded CRL data.
            issue_date (datetime): The CRL issue date (last_update field).
            next_update (datetime): The CRL next_update date.
        """
        db_name = self.__config["database"]
        cursor = self._local.connection.cursor(buffered=True)
        cursor.execute(f"USE {db_name}")
        cursor.execute("SELECT id FROM CertificateRevocationLists WHERE ca_id = %s", (ca_id,))
        row = cursor.fetchone()
        if row:
            cursor.execute(
                """UPDATE CertificateRevocationLists
                      SET crl_data = %s, issue_date = %s, next_update = %s
                    WHERE ca_id = %s""",
                (crl_pem, issue_date, next_update, ca_id)
            )
        else:
            cursor.execute(
                """INSERT INTO CertificateRevocationLists (ca_id, crl_data, issue_date, next_update)
                   VALUES (%s, %s, %s, %s)""",
                (ca_id, crl_pem, issue_date, next_update)
            )
        self._local.connection.commit()
        cursor.close()


    def get_estaliases_collection(self):
        """
        Retrieves all EST aliases from the ESTAliases table.

        Note: password_hash is included in the raw row; callers that expose data
        to the web UI should omit that field.

        Returns:
            list[dict]: Each dict contains id, name, ca_id, template_id,
                        is_default, username, password_hash, cert_fingerprint,
                        created_at, updated_at. Empty list on error.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")

            query = "SELECT * FROM ESTAliases"
            cursor.execute(query)
            estaliases_collection = cursor.fetchall()  # Fetch all results

            return estaliases_collection

        except mysql.connector.Error as e:
            logger.error(f"Database error: {e}")
            return []

        finally:
            if 'cursor' in locals():
                cursor.close()


    def get_est_alias(self, alias_id: int):
        """
        Retrieve a single EST alias by primary key.

        Args:
            alias_id (int): The alias ID.

        Returns:
            dict or None: Row with all ESTAliases columns, or None if not found.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT * FROM ESTAliases WHERE id = %s", (alias_id,))
            result = cursor.fetchone()
            return result
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None
        finally:
            if 'cursor' in locals():
                cursor.close()


    def create_est_alias(self, name: str, ca_id: int, template_id: int,
                         username: str, password_hash: str,
                         cert_fingerprint: str = None):
        """
        Insert a new EST alias into ESTAliases.

        Args:
            name (str): Unique label used as the EST URL path segment.
            ca_id (int): FK to CertificationAuthorities.
            template_id (int): FK to CertificateTemplates.
            username (str): Username for Basic Authentication.
            password_hash (str): Hashed password (werkzeug PBKDF2).
            cert_fingerprint (str): Certificate fingerprint for future mTLS use.

        Returns:
            int: The new alias ID, or None on error.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                """INSERT INTO ESTAliases
                       (name, ca_id, template_id, username, password_hash, cert_fingerprint)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (name, ca_id, template_id, username, password_hash, cert_fingerprint)
            )
            self._local.connection.commit()
            return cursor.lastrowid
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None
        finally:
            if 'cursor' in locals():
                cursor.close()


    def update_est_alias(self, alias_id: int, name: str, ca_id: int,
                         template_id: int, username: str,
                         password_hash: str = None,
                         cert_fingerprint: str = None):
        """
        Update an existing EST alias.

        If password_hash is None the stored hash is left unchanged.

        Args:
            alias_id (int): The alias to update.
            name (str): New alias name.
            ca_id (int): New CA FK.
            template_id (int): New template FK.
            username (str): New username for Basic Authentication.
            password_hash (str | None): New hashed password, or None to keep existing.
            cert_fingerprint (str | None): New certificate fingerprint.

        Returns:
            bool: True if a row was updated, False otherwise.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            if password_hash is not None:
                cursor.execute(
                    """UPDATE ESTAliases
                          SET name = %s, ca_id = %s, template_id = %s,
                              username = %s, password_hash = %s, cert_fingerprint = %s
                        WHERE id = %s""",
                    (name, ca_id, template_id, username, password_hash, cert_fingerprint, alias_id)
                )
            else:
                cursor.execute(
                    """UPDATE ESTAliases
                          SET name = %s, ca_id = %s, template_id = %s,
                              username = %s, cert_fingerprint = %s
                        WHERE id = %s""",
                    (name, ca_id, template_id, username, cert_fingerprint, alias_id)
                )
            self._local.connection.commit()
            return cursor.rowcount > 0
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()


    def delete_est_alias(self, alias_id: int):
        """
        Delete an EST alias by primary key.

        Args:
            alias_id (int): The alias ID to delete.

        Returns:
            bool: True if a row was deleted, False otherwise.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("DELETE FROM ESTAliases WHERE id = %s", (alias_id,))
            self._local.connection.commit()
            return cursor.rowcount > 0
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()


    def set_default_est_alias(self, alias_id: int):
        """
        Mark one alias as the default, clearing the flag on all others.

        Executed as two sequential statements in the same transaction so the
        table always has at most one default row.

        Args:
            alias_id (int): The alias that should become the new default.

        Returns:
            bool: True on success, False on database error.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("UPDATE ESTAliases SET is_default = FALSE")
            cursor.execute("UPDATE ESTAliases SET is_default = TRUE WHERE id = %s", (alias_id,))
            self._local.connection.commit()
            return True
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()


    # ── User management ───────────────────────────────────────────────────────

    def get_users(self):
        """Return all users, never exposing password_hash."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("""
                SELECT id, username, role, is_active, last_login, created_at, updated_at
                FROM Users
                ORDER BY username
            """)
            rows = cursor.fetchall()
            cursor.close()
            return rows
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return []

    def get_user(self, user_id):
        """Return a single user by id, never exposing password_hash."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("""
                SELECT id, username, role, is_active, last_login, created_at, updated_at
                FROM Users WHERE id = %s
            """, (user_id,))
            row = cursor.fetchone()
            cursor.close()
            return row
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None

    def create_user(self, username, password_hash, role):
        """Insert a new user. Returns the new id, or None on failure.
        Raises ValueError('username_taken') if the username already exists."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor()
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, password_hash, role)
            )
            self._local.connection.commit()
            new_id = cursor.lastrowid
            cursor.close()
            return new_id
        except mysql.connector.IntegrityError as err:
            if err.errno == 1062:
                raise ValueError("username_taken")
            logger.error(f"Database error: {err}")
            return None
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None

    def update_user(self, user_id, fields: dict):
        """
        Update mutable user fields. Accepted keys: username, password_hash, role, is_active.
        password_hash is only updated when present in the dict.
        """
        allowed = {'username', 'password_hash', 'role', 'is_active'}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor()
            cursor.execute(f"USE {db_name}")
            set_clause = ", ".join(f"`{k}` = %s" for k in updates)
            values = list(updates.values()) + [user_id]
            cursor.execute(f"UPDATE Users SET {set_clause} WHERE id = %s", values)
            self._local.connection.commit()
            affected = cursor.rowcount
            cursor.close()
            return affected > 0
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return False

    def delete_user(self, user_id):
        """Delete a user by id. Returns True if a row was removed."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor()
            cursor.execute(f"USE {db_name}")
            cursor.execute("DELETE FROM Users WHERE id = %s", (user_id,))
            self._local.connection.commit()
            affected = cursor.rowcount
            cursor.close()
            return affected > 0
        except mysql.connector.IntegrityError as err:
            if err.errno == 1062:
                raise ValueError("username_taken")
            logger.error(f"Database error: {err}")
            return False
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return False

    def get_user_by_username(self, username: str):
        """Return a single user including password_hash (for authentication only)."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("""
                SELECT id, username, password_hash, role, is_active, last_login, created_at
                FROM Users WHERE username = %s
            """, (username,))
            row = cursor.fetchone()
            cursor.close()
            return row
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")
            return None

    def update_last_login(self, user_id: int):
        """Set last_login = NOW() for the given user."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor()
            cursor.execute(f"USE {db_name}")
            cursor.execute("UPDATE Users SET last_login = NOW() WHERE id = %s", (user_id,))
            self._local.connection.commit()
            cursor.close()
        except mysql.connector.Error as err:
            logger.error(f"Database error: {err}")

    # ── Audit Logs ────────────────────────────────────────────────────────────

    def write_audit_log(self, resource_type: str, resource_id, action: str, user_id: int = 0):
        """Insert an audit log entry. user_id=0 means automated/system action."""
        if self._local.connection:
            cursor = self._local.connection.cursor()
            try:
                cursor.execute(
                    "INSERT INTO AuditLogs (resource_type, resource_id, action, user_id) VALUES (%s, %s, %s, %s)",
                    (resource_type, resource_id, action, user_id)
                )
                self._local.connection.commit()
            except mysql.connector.Error as err:
                logger.error(f"Audit log write error: {err}")
            finally:
                cursor.close()

    def dump_and_clear_audit_logs(self):
        """
        Fetch every row from AuditLogs (with username), delete them all, and
        return the rows so the caller can write the CSV.  Both operations run
        inside the same connection; the DELETE is only committed after the
        SELECT succeeds.
        """
        if self._local.connection:
            cursor = self._local.connection.cursor(dictionary=True)
            try:
                cursor.execute(
                    "SELECT al.id, al.resource_type, al.resource_id, al.action, "
                    "al.user_id, u.username, al.created_at "
                    "FROM AuditLogs al "
                    "LEFT JOIN Users u ON u.id = al.user_id "
                    "ORDER BY al.id ASC"
                )
                rows = cursor.fetchall()
                cursor.execute("DELETE FROM AuditLogs")
                self._local.connection.commit()
                return rows
            except mysql.connector.Error as err:
                logger.error(f"Audit log dump/clear error: {err}")
                return []
            finally:
                cursor.close()
        return []

    def get_audit_logs(self, page: int = 1, per_page: int = 25):
        """Return (total, list_of_rows) for the audit log, newest first."""
        offset = (page - 1) * per_page
        if self._local.connection:
            cursor = self._local.connection.cursor(dictionary=True)
            try:
                cursor.execute("SELECT COUNT(*) AS cnt FROM AuditLogs")
                total = cursor.fetchone()["cnt"]
                cursor.execute(
                    "SELECT al.id, al.resource_type, al.resource_id, al.action, "
                    "al.user_id, u.username, al.created_at "
                    "FROM AuditLogs al "
                    "LEFT JOIN Users u ON u.id = al.user_id "
                    "ORDER BY al.id DESC "
                    "LIMIT %s OFFSET %s",
                    (per_page, offset)
                )
                rows = cursor.fetchall()
                return total, rows
            except mysql.connector.Error as err:
                logger.error(f"Audit log read error: {err}")
                return 0, []
            finally:
                cursor.close()
        return 0, []

    # ─────────────────────────────────────────────────────────────────────────

    def create_database(self):
        db_name = self.__config["database"]

        if self._local.connection:
            cursor = self._local.connection.cursor()

            cursor.execute(f"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'Password1$' WITH GRANT OPTION")
            cursor.execute(f"FLUSH PRIVILEGES;")
            cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")  # Drop the database if it exists
            cursor.execute(f"CREATE DATABASE {db_name}")         # Create the database

            # Now connect to the actual database
            self._local.connection.database = db_name

            # STEP 1: Create the tables without foreign keys

            # Use the specified database
            cursor.execute(f"USE {db_name}")

            # SQL for creating the tables without foreign keys
            tables_without_fk = {
                "KeyStorage": """
                    CREATE TABLE IF NOT EXISTS KeyStorage (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        certificate_id INT,
                        key_type VARCHAR(64),
                        private_key TEXT,
                        public_key TEXT,
                        storage_type ENUM('Encrypted', 'Plain', 'HSM') NOT NULL,
                        hsm_slot INT,
                        hsm_token_id VARCHAR(255),
                        token_password VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """,
                "CertificationAuthorities": """
                    CREATE TABLE IF NOT EXISTS CertificationAuthorities (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        contact_email VARCHAR(255),
                        certificate TEXT,
                        public_key TEXT,
                        ski VARCHAR(64),
                        private_key TEXT,
                        private_key_reference INT,
                        certificate_chain TEXT,
                        max_validity INT,
                        serial_number_length INT,
                        crl_validity  INT DEFAULT 365,
                        extensions JSON NOT NULL,
                        is_default BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "CertificateTemplates": """
                    CREATE TABLE IF NOT EXISTS CertificateTemplates (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        name VARCHAR(255) NOT NULL,
                        definition JSON NOT NULL,
                        is_default BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "Certificates": """
                    CREATE TABLE IF NOT EXISTS Certificates (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        ca_id INT,
                        template_id INT,
                        serial_number VARCHAR(255) NOT NULL,
                        subject_name VARCHAR(255),
                        issuer_name VARCHAR(255),
                        not_before DATETIME,
                        not_after DATETIME,
                        public_key TEXT,
                        private_key_reference INT,
                        status ENUM('Active', 'Revoked', 'Expired') NOT NULL DEFAULT 'Active',
                        revoked_at TIMESTAMP,
                        revocation_reason INT,
                        certificate_data TEXT,
                        fingerprint VARCHAR(128) NOT NULL UNIQUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        UNIQUE KEY uq_ca_serial (ca_id, serial_number)
                    );
                """,
                "ESTAliases": """
                    CREATE TABLE IF NOT EXISTS ESTAliases (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        name VARCHAR(255) NOT NULL,
                        ca_id INT,
                        template_id INT,
                        is_default BOOLEAN DEFAULT FALSE,
                        username VARCHAR(255),
                        password_hash VARCHAR(255),
                        cert_fingerprint VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "OCSPResponders": """
                    CREATE TABLE IF NOT EXISTS OCSPResponders (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        name VARCHAR(255) NOT NULL,
                        ca_id INT,
                        issuer_ski VARCHAR(128) NOT NULL UNIQUE,
                        issuer_certificate TEXT,
                        not_after DATETIME,
                        response_validity INT DEFAULT 1,
                        private_key TEXT,
                        private_key_reference INT,
                        certificate TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "CertificateRevocationLists": """
                    CREATE TABLE IF NOT EXISTS CertificateRevocationLists (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        ca_id INT,
                        crl_data TEXT,
                        issue_date TIMESTAMP,
                        next_update TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "AuditLogs": """
                    CREATE TABLE IF NOT EXISTS AuditLogs (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        resource_type VARCHAR(64) NOT NULL,
                        resource_id INT,
                        action VARCHAR(64) NOT NULL,
                        user_id INT NOT NULL DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """,
                "Users": """
                    CREATE TABLE IF NOT EXISTS Users (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        username VARCHAR(255) NOT NULL UNIQUE,
                        password_hash VARCHAR(255) NOT NULL,
                        role ENUM('superadmin', 'admin', 'user', 'auditor') NOT NULL DEFAULT 'user',
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        last_login TIMESTAMP NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """
            }

            # Create each table
            for table_name, create_statement in tables_without_fk.items():
                logger.info(f"Creating table: {table_name}")
                cursor.execute(create_statement)

            # STEP 2: Add foreign key constraints after tables are created
            
            # SQL for adding foreign keys with unique names
            foreign_keys = [
                """
                ALTER TABLE CertificationAuthorities
                ADD CONSTRAINT fk_cert_authority_private_key_reference
                FOREIGN KEY (private_key_reference) REFERENCES KeyStorage(id);
                """,
                """
                ALTER TABLE Certificates
                ADD CONSTRAINT fk_cert_ca_id
                FOREIGN KEY (ca_id) REFERENCES CertificationAuthorities(id);
                """,
                """
                ALTER TABLE Certificates
                ADD CONSTRAINT fk_cert_template_id
                FOREIGN KEY (template_id) REFERENCES CertificateTemplates(id);
                """,
                """
                ALTER TABLE Certificates
                ADD CONSTRAINT fk_cert_private_key_reference
                FOREIGN KEY (private_key_reference) REFERENCES KeyStorage(id);
                """,
                """
                ALTER TABLE ESTAliases
                ADD CONSTRAINT fk_estalias_ca_id
                FOREIGN KEY (ca_id) REFERENCES CertificationAuthorities(id);
                """,
                """
                ALTER TABLE OCSPResponders
                ADD CONSTRAINT fk_ocspresponders_ca_id
                FOREIGN KEY (ca_id) REFERENCES CertificationAuthorities(id);
                """,
                """
                ALTER TABLE ESTAliases
                ADD CONSTRAINT fk_estalias_template_id
                FOREIGN KEY (template_id) REFERENCES CertificateTemplates(id);
                """,
                """
                ALTER TABLE CertificateRevocationLists
                ADD CONSTRAINT fk_crl_cert_authority
                FOREIGN KEY (ca_id) REFERENCES CertificationAuthorities(id);
                """
            ]

            # Add foreign keys to the tables
            for fk_statement in foreign_keys:
                logger.info(f"Adding foreign key: {fk_statement}")
                cursor.execute(fk_statement)

            # Seed default superadmin account (password must be changed after first login)
            logger.info("Seeding default superadmin user")
            cursor.execute(
                "INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, 'superadmin')",
                ('superadmin', generate_password_hash('password'))
            )
            self._local.connection.commit()

            cursor.close()
            logger.info("New PKI DB created successfully!")
        else:
            logger.info("New PKI DB not created. Connection error!")
