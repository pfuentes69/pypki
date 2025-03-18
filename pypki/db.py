import json
import mysql.connector
from mysql.connector import OperationalError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from pypki.ca import CertificationAuthority


class PKIDataBase:
    def __init__(self, config_json = None):
        """Initialize the PKI Utilities class."""
        self.__config = {}
        self.__db_connection = None
        self.__connected = False
        if config_json:
            self.load_config(config_json)
        pass


    # Load database configuration from JSON dict
    def load_config(self, config):
        self.__config = config


    # Load database configuration from JSON file
    def load_config_json(self, config_json:str):
        self.__config = json.loads(config_json)


    # Connect to MySQL server and drop database if it exists, then create it
    def connect_to_db(self):
        if not self.__connected:
            try:
                self.__db_connection = mysql.connector.connect(
                    host=self.__config["host"],
                    port=self.__config["port"],
                    user=self.__config["user"],
                    password=self.__config["password"]
                )
                self.__connected = True
            except OperationalError as e:
                print(f"Error connecting to MySQL: {e}")
        pass


    def close_db(self):
        if self.__connected:
            # Close the connection
            self.__db_connection.close()
            self.__connected = False
        pass

    def insert_ca(self, ca: CertificationAuthority):
        """
        Method to insert a Certification Authority object into the database.
        """
        try:
            db_name = self.__config["database"]
            cursor = self.__db_connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            
            insert_query = """
                INSERT INTO CertificationAuthorities (
                    ca_name, certificate, private_key, 
                    max_validity, serial_number_length, 
                    crl_validity, extensions
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            data = (
                ca.get_config()["ca_name"],
                ca.get_config()["crypto"]["certificate"],
                ca.get_config()["crypto"]["private_key"],
                ca.get_config()["max_validity"],
                ca.get_config()["serial_number_length"],
                ca.get_config()["crl_validity"],
                json.dumps(ca.get_config()["extensions"])
            )

            cursor.execute(insert_query, data)
            self.__db_connection.commit()
            print("Certification Authority inserted successfully!")

        except mysql.connector.Error as err:
            print(f"Error inserting Certification Authority: {err}")
        finally:
            cursor.close()


    def get_ca_id_by_name(self, ca_name: str):
        try:
            db_name = self.__config["database"]
            cursor = self.__db_connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT id FROM CertificationAuthorities WHERE ca_name = %s
            """
            cursor.execute(query, (ca_name,))
            result = cursor.fetchone()
            cursor.close()
        
            return result[0] if result else None
        except mysql.connector.Error as err:
            print(f"Error: {err}")
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
            cursor = self.__db_connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT * FROM CertificationAuthorities WHERE id = %s
            """
            cursor.execute(query, (ca_id,))
            result = cursor.fetchone()
            cursor.close()
            
            return result if result else None
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return None

    def get_ca_collection(self):
        """
        Retrieves a collection of CA IDs and names from the CertificationAuthorities table.
        
        :param db_config: Dictionary containing database connection parameters.
        :return: List of dictionaries with 'id' and 'ca_name'.
        """
        try:
            db_name = self.__config["database"]
            cursor = self.__db_connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")

            query = "SELECT id, ca_name FROM CertificationAuthorities"
            cursor.execute(query)
            ca_collection = cursor.fetchall()  # Fetch all results

            return ca_collection

        except mysql.connector.Error as e:
            print(f"Database error: {e}")
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
            cursor = self.__db_connection.cursor(buffered=True)
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
            self.__db_connection.commit()
            print("Certificate Template inserted successfully!")

        except mysql.connector.Error as err:
            print(f"Error inserting Certificate Template: {err}")
        finally:
            cursor.close()


    def get_cert_template_id_by_name(self, cert_template_name: str):
        try:
            db_name = self.__config["database"]
            cursor = self.__db_connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT id FROM CertificateTemplates WHERE name = %s
            """
            cursor.execute(query, (cert_template_name,))
            result = cursor.fetchone()
            cursor.close()
        
            return result[0] if result else None
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return None


    def get_cert_template_record_by_id(self, cert_template_id: int):
        """
        Retrieves the record corresponding to a given 'cert_template_id' in the CertificateTemplates table.
        """
        try:
            db_name = self.__config["database"]
            cursor = self.__db_connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            query = """
                SELECT * FROM CertificateTemplates WHERE id = %s
            """
            cursor.execute(query, (cert_template_id,))
            result = cursor.fetchone()
            cursor.close()
            
            return result if result else None
        except mysql.connector.Error as err:
            print(f"Error: {err}")
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
            serial_number = cert.serial_number
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
            cursor = self.__db_connection.cursor(buffered=True)
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
            self.__db_connection.commit()
            print("Certificate inserted successfully!")

        except mysql.connector.Error as err:
            print(f"Database error: {err}")
        except Exception as e:
            print(f"Error processing certificate: {e}")
        finally:
            cursor.close()


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
        cursor = self.__db_connection.cursor(buffered=True)
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
        cursor = self.__db_connection.cursor(buffered=True, dictionary=True)
        cursor.execute(f"USE {db_name}")
        cursor.execute(query, params)
        result = cursor.fetchone()  # Retrieve one matching record
        cursor.close()

        return result  # Returns a dictionary or None if not found


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
            cursor = self.__db_connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(query, params)
            self.__db_connection.commit()  # Commit the changes to the database

            if cursor.rowcount > 0:  # Check if any row was affected (i.e., the certificate was updated)
                cursor.close()
                return True
            else:
                cursor.close()
                return False  # No certificate found or already revoked
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return False


    def fetch_used_serials(self) -> set:
        """
        Fetch all used serial numbers from the Certificates table.

        Args:
            db_config (dict): Database connection parameters.

        Returns:
            set: A set containing all used serial numbers.
        """
        used_serials = set()
        
        try:
            db_name = self.__config["database"]
            cursor = self.__db_connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            # Query to fetch all serial numbers
            query = "SELECT serial_number FROM Certificates"
            cursor.execute(query)

            # Fetch results and add to the set
            for (serial_number,) in cursor.fetchall():
                used_serials.add(serial_number)

        except mysql.connector.Error as err:
            print(f"Database error: {err}")

        finally:
            cursor.close()
        
        return used_serials


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
        cursor = self.__db_connection.cursor(dictionary=True, buffered=True)
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
            serial_number = int(row['serial_number'])
            revoked_at = row['revoked_at']
            revocation_reason = row['revocation_reason']
            
            # Ensure the revocation time is a datetime object
#            revoked_time = datetime.strptime(revoked_at, "%Y-%m-%d %H:%M:%S") if revoked_at else None
            
            # Add the certificate information to the revoked_certificates list
            revoked_certificates.append((serial_number, revoked_at, revocation_reason))
        
        # Close the cursor and the connection
        cursor.close()
        
        return revoked_certificates

    def create_database(self):
        db_name = self.__config["database"]

        if self.__db_connection:
            cursor = self.__db_connection.cursor()
            cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")  # Drop the database if it exists
            cursor.execute(f"CREATE DATABASE {db_name}")         # Create the database

            # Now connect to the actual database
            self.__db_connection.database = db_name

            # STEP 1: Create the tables without foreign keys

            # Use the specified database
            cursor.execute(f"USE {db_name}")

            # SQL for creating the tables without foreign keys
            tables_without_fk = {
                "PrivateKeyStorage": """
                    CREATE TABLE IF NOT EXISTS PrivateKeyStorage (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        certificate_id INT,
                        private_key TEXT,
                        storage_type ENUM('Encrypted', 'Plain', 'HSM') NOT NULL,
                        hsm_slot INT,
                        hsm_token_id VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """,
                "CertificationAuthorities": """
                    CREATE TABLE IF NOT EXISTS CertificationAuthorities (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        ca_name VARCHAR(255) NOT NULL,
                        description TEXT,
                        contact_email VARCHAR(255),
                        certificate TEXT,
                        public_key TEXT,
                        private_key TEXT,
                        private_key_reference INT,
                        max_validity INT,
                        serial_number_length INT,
                        crl_validity  INT DEFAULT 365,
                        extensions TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "CertificateTemplates": """
                    CREATE TABLE IF NOT EXISTS CertificateTemplates (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        name VARCHAR(255) NOT NULL,
                        definition JSON NOT NULL,
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
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "CertificateExtensions": """
                    CREATE TABLE IF NOT EXISTS CertificateExtensions (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        certificate_id INT,
                        extension_name VARCHAR(255) NOT NULL,
                        extension_value TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "CertificateLogs": """
                    CREATE TABLE IF NOT EXISTS CertificateLogs (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        certificate_id INT,
                        action ENUM('Issued', 'Revoked', 'Renewed', 'Updated', 'Expired') NOT NULL,
                        reason TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                        action_type VARCHAR(255),
                        action_details JSON,
                        user_id INT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """
            }

            # Create each table
            for table_name, create_statement in tables_without_fk.items():
                print(f"Creating table: {table_name}")
                cursor.execute(create_statement)

            # STEP 2: Add foreign key constraints after tables are created
            
            # SQL for adding foreign keys with unique names
            foreign_keys = [
                """
                ALTER TABLE CertificationAuthorities
                ADD CONSTRAINT fk_cert_authority_private_key_reference
                FOREIGN KEY (private_key_reference) REFERENCES PrivateKeyStorage(id);
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
                FOREIGN KEY (private_key_reference) REFERENCES PrivateKeyStorage(id);
                """,
                """
                ALTER TABLE CertificateExtensions
                ADD CONSTRAINT fk_extension_certificate_id
                FOREIGN KEY (certificate_id) REFERENCES Certificates(id);
                """,
                """
                ALTER TABLE CertificateLogs
                ADD CONSTRAINT fk_log_certificate_id
                FOREIGN KEY (certificate_id) REFERENCES Certificates(id);
                """,
                """
                ALTER TABLE CertificateRevocationLists
                ADD CONSTRAINT fk_crl_cert_authority
                FOREIGN KEY (ca_id) REFERENCES CertificationAuthorities(id);
                """
            ]

            # Add foreign keys to the tables
            for fk_statement in foreign_keys:
                print(f"Adding foreign key: {fk_statement}")
                cursor.execute(fk_statement)

            cursor.close()
            print("New PKI DB created successfully!")
        else:
            print("New PKI DB not created. Connection error!")
