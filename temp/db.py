import json
import mysql.connector
from mysql.connector import OperationalError

# Load database configuration from JSON file
def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

# Connect to MySQL server and drop database if it exists, then create it
def connect_to_db(config):
    try:
        connection = mysql.connector.connect(
            host=config["host"],
            port=config["port"],
            user=config["user"],
            password=config["password"]
        )
        return connection
    except OperationalError as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def drop_and_create_database(connection, db_name):
    cursor = connection.cursor()
    cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")  # Drop the database if it exists
    cursor.execute(f"CREATE DATABASE {db_name}")         # Create the database
    cursor.close()

# Create tables in the database without foreign keys first
def create_tables_without_foreign_keys(connection, db_name):
    cursor = connection.cursor()
    
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
                name VARCHAR(255) NOT NULL,
                description TEXT,
                contact_email VARCHAR(255),
                certificate_data TEXT,
                public_key TEXT,
                private_key TEXT,
                private_key_reference INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
        """,
        "CertificateTypes": """
            CREATE TABLE IF NOT EXISTS CertificateTypes (
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
                type_id INT,
                serial_number VARCHAR(255) NOT NULL,
                subject_name VARCHAR(255),
                issuer_name VARCHAR(255),
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                public_key TEXT,
                private_key_reference INT,
                status ENUM('Active', 'Revoked', 'Expired') NOT NULL DEFAULT 'Active',
                revoked_at TIMESTAMP,
                certificate_data TEXT,
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

    cursor.close()

# Add foreign key constraints after tables are created
def add_foreign_keys(connection, db_name):
    cursor = connection.cursor()
    
    # Use the specified database
    cursor.execute(f"USE {db_name}")

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
        ADD CONSTRAINT fk_cert_type_id
        FOREIGN KEY (type_id) REFERENCES CertificateTypes(id);
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

def main():
    # Load database configuration from the config file
    config = load_config()
    db_name = config["database"]
    
    # Connect to MySQL server
    connection = connect_to_db(config)
    
    if connection:
        # Drop the database if it exists and create it again
        drop_and_create_database(connection, db_name)

        # Now connect to the actual database
        connection.database = db_name

        # Create the tables without foreign keys
        create_tables_without_foreign_keys(connection, db_name)

        # Add the foreign keys
        add_foreign_keys(connection, db_name)

        # Close the connection
        connection.close()

if __name__ == "__main__":
    main()
