# certificates.py
import mysql.connector
from certificate import Certificate

class Certificates:
    def __init__(self, config):
        self.config = config
        self.connection = self.connect_to_db()

    def connect_to_db(self):
        """
        Method to establish the connection to the MySQL database.
        """
        try:
            connection = mysql.connector.connect(
                host=self.config["host"],
                port=self.config["port"],
                user=self.config["user"],
                password=self.config["password"],
                database=self.config["database"]
            )
            return connection
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return None

    def insert_certificate(self, certificate: Certificate):
        """
        Method to insert a Certificate object into the database.
        """
        try:
            cursor = self.connection.cursor()
            
            insert_query = """
                INSERT INTO Certificates (
                    serial_number, subject_name, issuer_name, 
                    not_before, not_after, public_key, private_key_reference, 
                    status, revoked_at, certificate_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            data = (
                certificate.serial_number,
                certificate.subject_name,
                certificate.issuer_name,
                certificate.not_before,
                certificate.not_after,
                certificate.public_key,
                certificate.private_key_reference,
                certificate.status,
                certificate.revoked_at,
                certificate.certificate_data
            )

            cursor.execute(insert_query, data)
            self.connection.commit()
            print("Certificate inserted successfully!")

        except mysql.connector.Error as err:
            print(f"Error inserting certificate: {err}")
        finally:
            cursor.close()

    def close_connection(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
