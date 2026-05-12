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
from datetime import datetime, timezone
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
        conn.cmd_query("SET time_zone = '+00:00'")
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


    # ── CryptoProviders helpers (Phase 0.1) ───────────────────────────────────
    #
    # CRUD over the CryptoProviders table. The full management API will be
    # built on top of these in a later phase — see doc/kms-specs.md §9.

    def insert_provider(self, label: str, kind: str, auth_secret_ref: str,
                        module_path: str = None, slot_label: str = None,
                        auth_kind: str = "pin", auto_activate: bool = False,
                        auth_secret_blob: bytes = None, extra_json: str = "{}",
                        description: str = None, is_default: bool = False) -> int:
        """
        Insert a CryptoProviders row. Returns the new row id, or None on error.

        `extra_json` must be a JSON-serialised string. Provider-level validation
        (e.g. auto_activate is incompatible with operator:prompt) is the
        caller's responsibility — this is a thin DB helper.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "INSERT INTO CryptoProviders ("
                "    label, kind, module_path, slot_label, auth_kind, auto_activate, "
                "    auth_secret_ref, auth_secret_blob, extra_json, description, is_default"
                ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (label, kind, module_path, slot_label, auth_kind, auto_activate,
                 auth_secret_ref, auth_secret_blob, extra_json, description, is_default)
            )
            self._local.connection.commit()
            new_id = cursor.lastrowid
            cursor.close()
            logger.info(f"Inserted CryptoProviders id={new_id} label='{label}' kind={kind}")
            return new_id
        except mysql.connector.Error as err:
            logger.error(f"Error inserting CryptoProviders record: {err}")
            return None

    def get_provider_by_id(self, provider_id: int):
        """Retrieve a CryptoProviders row by id. Returns a dict or None."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT * FROM CryptoProviders WHERE id = %s", (provider_id,))
            result = cursor.fetchone()
            cursor.close()
            return result if result else None
        except mysql.connector.Error as err:
            logger.error(f"Error retrieving CryptoProviders record: {err}")
            return None

    def get_provider_by_label(self, label: str):
        """Retrieve a CryptoProviders row by label. Returns a dict or None."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT * FROM CryptoProviders WHERE label = %s", (label,))
            result = cursor.fetchone()
            cursor.close()
            return result if result else None
        except mysql.connector.Error as err:
            logger.error(f"Error retrieving CryptoProviders record by label: {err}")
            return None

    def list_providers(self):
        """List all CryptoProviders rows ordered by id."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT * FROM CryptoProviders ORDER BY id")
            results = cursor.fetchall()
            cursor.close()
            return results or []
        except mysql.connector.Error as err:
            logger.error(f"Error listing CryptoProviders: {err}")
            return []

    def kek_wrap_pem(self, pem_text: str):
        """
        Public wrapper around :meth:`_encrypt_pem_under_default_provider`
        that handles its own connection / cursor. Returns
        ``(provider_id, ciphertext_b64)`` so callers in ``core.py`` can
        encrypt PEM material under the per-provider KEK without owning a
        cursor themselves.
        """
        with self.connection():
            cursor = self._local.connection.cursor(buffered=True)
            try:
                return self._encrypt_pem_under_default_provider(cursor, pem_text)
            finally:
                cursor.close()


    def _encrypt_pem_under_default_provider(self, cursor, pem_text: str):
        """
        Resolve the default crypto provider, derive its KEK, encrypt the PEM,
        and return (provider_id, ciphertext_blob_b64). Used by inline insert
        paths (insert_ca, OCSP responder inserts) so new software keys land
        in `KeyStorage` already encrypted at rest.

        Raises RuntimeError if the default provider does not exist or its
        secret cannot be resolved (e.g. HSM_PIN_KEK is not set).
        """
        # Local import — keep cryptography KDF/AEAD off the module load path.
        from .key_encryption import get_provider_kek, encrypt_pem, KEKUnavailable
        cursor.execute(
            "SELECT * FROM CryptoProviders WHERE is_default = TRUE LIMIT 1"
        )
        cols = [d[0] for d in cursor.description]
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError(
                "No default crypto provider found; cannot encrypt-at-rest software keys. "
                "Run reset_pki or apply migrations to seed 'software-default'."
            )
        provider = dict(zip(cols, row))
        try:
            kek = get_provider_kek(provider)
        except KEKUnavailable as e:
            raise RuntimeError(
                f"Cannot encrypt-at-rest software key under provider "
                f"id={provider['id']} ('{provider['label']}'): {e}"
            )
        pem_bytes = pem_text.encode("utf-8") if isinstance(pem_text, str) else pem_text
        blob = encrypt_pem(pem_bytes, kek)
        return provider["id"], blob


    @staticmethod
    def validate_provider_auth_config(record: dict) -> None:
        """
        Enforce the cross-field consistency rules from kms-specs.md §4.1
        on a CryptoProviders row before it is persisted:

          - auto_activate=TRUE  → auth_secret_ref must be one of
                                  db:encrypted | env:NAME | vault:path
          - auto_activate=FALSE → auth_secret_ref must be operator:prompt
          - auth_secret_blob is non-null iff auth_secret_ref='db:encrypted'

        Raises :class:`ValueError` with a single human-readable message on
        the first violation; safe to call from API handlers.
        """
        ref = (record.get("auth_secret_ref") or "").strip()
        auto = bool(record.get("auto_activate"))
        blob = record.get("auth_secret_blob")
        label = record.get("label") or "<unnamed>"

        is_operator = (ref == "operator:prompt")
        is_db_enc = (ref == "db:encrypted")
        is_env = ref.startswith("env:")
        is_vault = ref.startswith("vault:")

        if not (is_operator or is_db_enc or is_env or is_vault):
            raise ValueError(
                f"Provider '{label}': auth_secret_ref must be one of "
                f"'db:encrypted', 'env:NAME', 'vault:PATH', or 'operator:prompt' "
                f"(got {ref!r})"
            )

        if auto and is_operator:
            raise ValueError(
                f"Provider '{label}': auto_activate=TRUE is incompatible with "
                f"auth_secret_ref='operator:prompt' — auto-activated providers "
                f"must resolve their PIN without operator interaction"
            )
        if not auto and not is_operator:
            raise ValueError(
                f"Provider '{label}': auto_activate=FALSE requires "
                f"auth_secret_ref='operator:prompt' (got {ref!r}); operator-prompt "
                f"is the only resolver that supplies the PIN at runtime"
            )

        if is_db_enc and not blob:
            raise ValueError(
                f"Provider '{label}': auth_secret_ref='db:encrypted' requires "
                f"auth_secret_blob to be populated"
            )
        if blob and not is_db_enc:
            raise ValueError(
                f"Provider '{label}': auth_secret_blob is set but "
                f"auth_secret_ref={ref!r} (auth_secret_blob is only valid for "
                f"'db:encrypted')"
            )


    def get_default_provider_id(self):
        """Return the id of the provider with is_default=TRUE, or None."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "SELECT id FROM CryptoProviders WHERE is_default = TRUE LIMIT 1"
            )
            row = cursor.fetchone()
            cursor.close()
            return row[0] if row else None
        except mysql.connector.Error as err:
            logger.error(f"Error retrieving default provider id: {err}")
            return None

    # Mutable provider fields per kms-specs.md §9.1 (POST/PUT). `kind`
    # and `is_default` are intentionally *not* in this set — kind is
    # immutable after creation, is_default flips through a dedicated path.
    _PROVIDER_UPDATABLE = frozenset({
        "label", "module_path", "slot_label", "auth_kind",
        "auto_activate", "auth_secret_ref", "auth_secret_blob",
        "extra_json", "description",
    })

    def update_provider(self, provider_id: int, fields: dict) -> bool:
        """
        Update mutable fields on a CryptoProviders row. Unknown fields are
        ignored. Returns True if the row was updated, False on no-op or
        DB error. The caller is responsible for running
        :meth:`validate_provider_auth_config` on the resulting record
        beforehand.
        """
        updates = {k: v for k, v in fields.items() if k in self._PROVIDER_UPDATABLE}
        if not updates:
            return False
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            set_clause = ", ".join(f"{col} = %s" for col in updates)
            values = list(updates.values()) + [provider_id]
            cursor.execute(
                f"UPDATE CryptoProviders SET {set_clause} WHERE id = %s",
                values,
            )
            self._local.connection.commit()
            affected = cursor.rowcount
            cursor.close()
            return affected > 0
        except mysql.connector.Error as err:
            logger.error(f"Error updating CryptoProviders: {err}")
            return False

    def count_provider_keys(self, provider_id: int) -> int:
        """Count KeyStorage rows that belong to this provider."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "SELECT COUNT(*) FROM KeyStorage WHERE provider_id = %s",
                (provider_id,),
            )
            row = cursor.fetchone()
            cursor.close()
            return int(row[0]) if row else 0
        except mysql.connector.Error as err:
            logger.error(f"Error counting provider keys: {err}")
            return 0

    def delete_provider(self, provider_id: int):
        """
        Delete a provider row. Returns:
          - {"deleted": True}      on success
          - {"deleted": False, "reason": "...", "key_count": N}  if blocked
          - None                   if the provider does not exist

        Refuses if any KeyStorage row references this provider, or if the
        provider is the default. The caller's REST handler should map
        those cases to 409 Conflict.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "SELECT id, is_default FROM CryptoProviders WHERE id = %s",
                (provider_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.close()
                return None
            if row.get("is_default"):
                cursor.close()
                return {"deleted": False, "reason": "is_default"}

            cursor.execute(
                "SELECT COUNT(*) AS n FROM KeyStorage WHERE provider_id = %s",
                (provider_id,),
            )
            n = int(cursor.fetchone()["n"])
            if n > 0:
                cursor.close()
                return {"deleted": False, "reason": "has_keys", "key_count": n}

            cursor.execute(
                "DELETE FROM CryptoProviders WHERE id = %s", (provider_id,),
            )
            self._local.connection.commit()
            cursor.close()
            return {"deleted": True}
        except mysql.connector.Error as err:
            logger.error(f"Error deleting CryptoProviders: {err}")
            return {"deleted": False, "reason": "db_error", "error": str(err)}

    # ── Key listing / usage / deletion (Phase 5a) ─────────────────────────────

    def list_keys(self, provider_id: int = None, key_type: str = None):
        """
        List KeyStorage rows with optional filters. Returns dicts that omit
        the private_key column (callers should never see encrypted material
        through the management API).
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            where = []
            params = []
            if provider_id is not None:
                where.append("provider_id = %s")
                params.append(provider_id)
            if key_type:
                where.append("key_type = %s")
                params.append(key_type)
            where_sql = (" WHERE " + " AND ".join(where)) if where else ""
            cursor.execute(
                "SELECT id, provider_id, key_type, public_key, label, "
                "       storage_type, hsm_token_id, key_owned, created_at "
                f"FROM KeyStorage{where_sql} ORDER BY id",
                params,
            )
            rows = cursor.fetchall() or []
            cursor.close()
            return rows
        except mysql.connector.Error as err:
            logger.error(f"Error listing KeyStorage: {err}")
            return []

    def count_key_usage(self, key_id: int) -> dict:
        """
        How many CAs / OCSP responders / certificates reference this key?
        Used by delete_key to refuse removal of an in-use key (kms-specs
        §9.2 — DELETE returns 409 when usage > 0).
        """
        out = {"cas": 0, "ocsp_responders": 0, "certificates": 0}
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "SELECT COUNT(*) FROM CertificationAuthorities "
                "WHERE private_key_reference = %s", (key_id,),
            )
            out["cas"] = int(cursor.fetchone()[0])
            cursor.execute(
                "SELECT COUNT(*) FROM OCSPResponders "
                "WHERE private_key_reference = %s", (key_id,),
            )
            out["ocsp_responders"] = int(cursor.fetchone()[0])
            cursor.execute(
                "SELECT COUNT(*) FROM Certificates "
                "WHERE private_key_reference = %s", (key_id,),
            )
            out["certificates"] = int(cursor.fetchone()[0])
            cursor.close()
        except mysql.connector.Error as err:
            logger.error(f"Error counting key usage: {err}")
        out["total"] = out["cas"] + out["ocsp_responders"] + out["certificates"]
        return out

    def delete_key(self, key_id: int):
        """
        Delete a KeyStorage row. Returns:
          - {"deleted": True}                        on success
          - {"deleted": False, "reason": "in_use", "usage": {...}}
          - None                                     if the row does not exist

        The on-token deletion for HSM keys is the caller's responsibility
        (KMS dispatches to PKCS11Backend.delete_key first, then this row).
        """
        usage = self.count_key_usage(key_id)
        if usage.get("total", 0) > 0:
            return {"deleted": False, "reason": "in_use", "usage": usage}
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT id FROM KeyStorage WHERE id = %s", (key_id,))
            if cursor.fetchone() is None:
                cursor.close()
                return None
            cursor.execute("DELETE FROM KeyStorage WHERE id = %s", (key_id,))
            self._local.connection.commit()
            cursor.close()
            return {"deleted": True}
        except mysql.connector.Error as err:
            logger.error(f"Error deleting KeyStorage row: {err}")
            return {"deleted": False, "reason": "db_error", "error": str(err)}


    def insert_key(self, private_key: str, storage_type: str = "Plain",
                   public_key: str = None, key_type: str = None,
                   hsm_slot: int = None, hsm_token_id: str = None,
                   token_password: str = None,
                   provider_id: int = None, label: str = None,
                   key_owned: bool = True) -> int:
        """
        Insert a row into KeyStorage. Returns the new row id.

        For software keys only private_key, storage_type, public_key, and
        key_type are used.  For HSM keys also pass hsm_slot, hsm_token_id,
        and token_password.

        ``key_owned`` controls whether ``KMS.delete_key`` cascades to the
        on-token objects:
          - ``True`` (default): pyPKI generated this key, so deletion
            destroys the on-token objects too.
          - ``False``: the operator imported a pre-existing on-token key;
            deletion only removes the pyPKI registration.

        If ``provider_id`` is not supplied the row is bound to the default
        crypto provider so every new key has a provider — see
        doc/kms-specs.md §3-4.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            if provider_id is None:
                cursor.execute(
                    "SELECT id FROM CryptoProviders WHERE is_default = TRUE LIMIT 1"
                )
                row = cursor.fetchone()
                if row is not None:
                    provider_id = row[0]

            cursor.execute(
                "INSERT INTO KeyStorage "
                "(provider_id, private_key, storage_type, public_key, key_type, "
                " label, hsm_slot, hsm_token_id, token_password, key_owned) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (provider_id, private_key, storage_type, public_key, key_type,
                 label, hsm_slot, hsm_token_id, token_password, bool(key_owned))
            )
            self._local.connection.commit()
            new_id = cursor.lastrowid
            cursor.close()
            logger.info(
                f"Inserted KeyStorage id={new_id} provider_id={provider_id} "
                f"storage_type={storage_type} key_owned={bool(key_owned)}"
            )
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

            # Derive key type label
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                key_type = f"ECDSA-{public_key.curve.name}"
            else:
                key_type = f"RSA-{public_key.key_size}"

            # SKI: prefer the extension already embedded in the certificate (it is exactly
            # what OCSP clients hash to compute issuer_key_hash).  Fall back to computing
            # SHA-1 of the BIT STRING *value* from SubjectPublicKeyInfo — not the full SPKI
            # structure — which is what RFC 5280 §4.2.1.2 Method 1 specifies:
            #   EC  → SHA-1 of the uncompressed EC point
            #   RSA → SHA-1 of the PKCS#1 DER (RSAPublicKey), i.e. PublicFormat.PKCS1
            try:
                ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                ski = ski_ext.value.digest.hex()
            except x509.ExtensionNotFound:
                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )
                else:
                    key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
                digest = hashes.Hash(hashes.SHA1())
                digest.update(key_bytes)
                ski = digest.finalize().hex()

            # Resolve private_key_reference and key ownership. Two paths:
            #   1. kms_key_id supplied → reuse an existing KeyStorage row (key_owned=False).
            #      The key existed before the CA, so deleting the CA must NOT delete it.
            #   2. private_key PEM supplied → insert a new KeyStorage row (key_owned=True).
            #      The key was created with the CA, so deleting the CA cascades to it.
            # Validation that the kms_key_id exists, matches the cert's public key,
            # and is not already used by another CA is performed by the caller
            # (see web.services.api_adapters._verify_kms_key_for_ca).
            crypto = ca.get_config()["crypto"]
            kms_key_id = crypto.get("kms_key_id")
            private_key_pem = crypto.get("private_key")

            if kms_key_id is not None:
                private_key_reference = int(kms_key_id)
                key_owned = False
                logger.info(f"CA bound to existing KeyStorage id={private_key_reference} (not owned)")
            elif private_key_pem:
                pub_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
                default_provider_id, enc_blob = self._encrypt_pem_under_default_provider(
                    cursor, private_key_pem
                )
                cursor.execute(
                    "INSERT INTO KeyStorage (provider_id, private_key, storage_type, public_key, key_type) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (default_provider_id, enc_blob, "Encrypted", pub_key_pem, key_type)
                )
                private_key_reference = cursor.lastrowid
                key_owned = True
                logger.info(f"CA private key stored encrypted in KeyStorage id={private_key_reference} provider_id={default_provider_id}")
            else:
                private_key_reference = None
                key_owned = True

            insert_query = """
                INSERT INTO CertificationAuthorities (
                    name, certificate, ski, private_key_reference, key_owned, certificate_chain,
                    max_validity, serial_number_length,
                    crl_validity, extensions
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            data = (
                ca.get_config()["ca_name"],
                ca.get_config()["crypto"]["certificate"],
                ski,
                private_key_reference,
                key_owned,
                ca.get_config()["crypto"]["certificate_chain"],
                ca.get_config()["max_validity"],
                ca.get_config()["serial_number_length"],
                ca.get_config()["crl_validity"],
                json.dumps(ca.get_config()["extensions"])
            )

            cursor.execute(insert_query, data)
            new_id = cursor.lastrowid
            self._local.connection.commit()
            logger.info(f"Certification Authority inserted successfully! New ID: {new_id}")
            return new_id

        except mysql.connector.Error as err:
            logger.error(f"Error inserting Certification Authority: {err}")
            raise
        finally:
            cursor.close()


    def get_ca_id_by_key_reference(self, key_id: int):
        """
        Return the id of the CA that already references the given KeyStorage
        row, or None if no CA references it.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute(
                "SELECT id FROM CertificationAuthorities WHERE private_key_reference = %s",
                (key_id,)
            )
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result else None
        except mysql.connector.Error as err:
            logger.error(err)
            return None


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

    def delete_ca(self, ca_id: int) -> dict:
        """
        Delete a CA and all its directly dependent resources in a single transaction.

        Deletion order (avoids FK violations):
          1. OCSPResponders       WHERE ca_id = ?   → deleted
          2. ESTAliases           WHERE ca_id = ?   → deleted
          3. CertificateRevocationLists WHERE ca_id = ? → deleted
          4. Certificates         WHERE ca_id = ?   → ca_id set to NULL (records preserved)
          5. CertificationAuthorities WHERE id = ?  → deleted
          6. KeyStorage           WHERE id = private_key_reference → deleted only
                                  if key_owned = TRUE (CAs bound to a pre-existing
                                  KMS key keep the key on delete)

        Returns a dict with counts of affected rows per table, or raises on error.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True, dictionary=True)
            cursor.execute(f"USE {db_name}")

            # Capture private_key_reference and ownership flag before deletion
            cursor.execute(
                "SELECT private_key_reference, key_owned FROM CertificationAuthorities WHERE id = %s",
                (ca_id,)
            )
            ca_row = cursor.fetchone()
            if not ca_row:
                cursor.close()
                return None
            key_ref = ca_row["private_key_reference"]
            key_owned = bool(ca_row["key_owned"])

            stats = {}

            cursor.execute("DELETE FROM OCSPResponders WHERE ca_id = %s", (ca_id,))
            stats["ocsp_responders_deleted"] = cursor.rowcount

            cursor.execute("DELETE FROM ESTAliases WHERE ca_id = %s", (ca_id,))
            stats["est_aliases_deleted"] = cursor.rowcount

            cursor.execute("DELETE FROM CertificateRevocationLists WHERE ca_id = %s", (ca_id,))
            stats["crls_deleted"] = cursor.rowcount

            cursor.execute(
                "UPDATE Certificates SET ca_id = NULL WHERE ca_id = %s", (ca_id,)
            )
            stats["certificates_unlinked"] = cursor.rowcount

            cursor.execute(
                "DELETE FROM CertificationAuthorities WHERE id = %s", (ca_id,)
            )
            stats["ca_deleted"] = cursor.rowcount

            if key_ref and key_owned:
                cursor.execute("DELETE FROM KeyStorage WHERE id = %s", (key_ref,))
                stats["key_deleted"] = cursor.rowcount
                stats["key_preserved"] = 0
            else:
                stats["key_deleted"] = 0
                stats["key_preserved"] = 1 if key_ref else 0

            self._local.connection.commit()
            logger.info(f"CA id={ca_id} deleted: {stats}")
            return stats

        except mysql.connector.Error as err:
            self._local.connection.rollback()
            logger.error(f"Error deleting CA id={ca_id}: {err}")
            raise
        finally:
            cursor.close()

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
                default_provider_id, enc_blob = self._encrypt_pem_under_default_provider(
                    cursor, private_key_pem
                )
                cursor.execute(
                    "INSERT INTO KeyStorage (provider_id, private_key, storage_type, public_key, key_type) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (default_provider_id, enc_blob, "Encrypted", pub_key_pem, key_type)
                )
                private_key_reference = cursor.lastrowid
                logger.info(f"OCSP responder private key stored encrypted in KeyStorage id={private_key_reference} provider_id={default_provider_id}")

            # Resolve the issuing CA by its SKI so we can populate ca_id
            issuer_ski = ocsp_resp.get_config()["issuer_ski"]
            cursor.execute(
                "SELECT id FROM CertificationAuthorities WHERE ski = %s",
                (issuer_ski,)
            )
            ca_row = cursor.fetchone()
            ca_id = ca_row[0] if ca_row else None
            if ca_id is None:
                logger.warning(
                    f"insert_ocsp_responder: no CA found with ski='{issuer_ski}'; "
                    "ca_id will be NULL"
                )

            insert_query = """
                INSERT INTO OCSPResponders (
                    name, ca_id, issuer_ski, issuer_certificate,
                    private_key_reference, certificate, response_validity
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """

            data = (
                ocsp_resp.get_config()["name"],
                ca_id,
                issuer_ski,
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


    def insert_ocsp_responder_from_dict(self, data: dict) -> int:
        """
        Insert an OCSP Responder from a plain dict (web-form path).

        Expected keys:
            name, ca_id, issuer_ski, issuer_certificate,
            certificate (responder cert PEM), private_key (PEM),
            response_validity_hours, nonce_policy, include_cert_in_response,
            responder_id_encoding, hash_algorithm.

        Returns the new row id.
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")

            # Store private key in KeyStorage
            private_key_reference = None
            private_key_pem = data.get("private_key")
            cert_pem = data.get("certificate")
            if private_key_pem:
                pub_key_pem = None
                key_type = None
                if cert_pem:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
                    public_key = cert.public_key()
                    pub_key_pem = public_key.public_bytes(
                        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                    ).decode()
                    if isinstance(public_key, ec.EllipticCurvePublicKey):
                        key_type = f"ECDSA-{public_key.curve.name}"
                    else:
                        key_type = f"RSA-{public_key.key_size}"
                default_provider_id, enc_blob = self._encrypt_pem_under_default_provider(
                    cursor, private_key_pem
                )
                cursor.execute(
                    "INSERT INTO KeyStorage (provider_id, private_key, storage_type, public_key, key_type)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (default_provider_id, enc_blob, "Encrypted", pub_key_pem, key_type)
                )
                private_key_reference = cursor.lastrowid
                logger.info(f"OCSP responder private key stored encrypted in KeyStorage id={private_key_reference} provider_id={default_provider_id}")

            response_validity_hours = int(data.get("response_validity_hours") or 24)
            cursor.execute("""
                INSERT INTO OCSPResponders (
                    name, ca_id, issuer_ski, issuer_certificate,
                    private_key_reference, certificate,
                    response_validity, response_validity_hours,
                    nonce_policy, include_cert_in_response,
                    responder_id_encoding, hash_algorithm
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data["name"],
                data.get("ca_id"),
                data["issuer_ski"],
                data["issuer_certificate"],
                private_key_reference,
                cert_pem,
                max(1, response_validity_hours // 24),   # legacy days column
                response_validity_hours,
                data.get("nonce_policy") or "optional",
                bool(data.get("include_cert_in_response", True)),
                data.get("responder_id_encoding") or "hash",
                data.get("hash_algorithm") or "sha1",
            ))
            new_id = cursor.lastrowid
            self._local.connection.commit()
            logger.info(f"OCSP Responder inserted with id={new_id}")
            return new_id

        except mysql.connector.Error as err:
            logger.error(f"Error inserting OCSP Responder: {err}")
            raise
        finally:
            if 'cursor' in locals():
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
                    response_validity_hours=row.get('response_validity_hours') or (row['response_validity'] * 24),
                    certificate_pem=row['certificate'],
                    kms_key_id=row.get('private_key_reference'),
                    ca_id=row.get('ca_id'),
                    nonce_policy=row.get('nonce_policy') or 'optional',
                    include_cert_in_response=bool(row.get('include_cert_in_response', True)),
                    responder_id_encoding=row.get('responder_id_encoding') or 'hash',
                    hash_algorithm=row.get('hash_algorithm') or 'sha1',
                )
                ocsp_responders.append(responder)

            return ocsp_responders

        except mysql.connector.Error as e:
            logger.error(f"Database error: {e}")
            return []

        finally:
            if 'cursor' in locals():
                cursor.close()


    def get_ocsp_responders_list(self):
        """
        Returns a list of dicts with display fields for all OCSP responders
        (no certificate/key material — suitable for the management UI).
        """
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("""
                SELECT r.id, r.name, r.ca_id, r.issuer_ski,
                       r.response_validity, r.response_validity_hours,
                       r.nonce_policy, r.include_cert_in_response,
                       r.responder_id_encoding, r.hash_algorithm,
                       r.not_after, r.certificate,
                       ca.name AS ca_name
                FROM OCSPResponders r
                LEFT JOIN CertificationAuthorities ca ON ca.id = r.ca_id
                ORDER BY r.name
            """)
            rows = cursor.fetchall()
            result = []
            for row in rows:
                # Extract subject CN from certificate PEM for display
                cert_subject = None
                cert_not_after = None
                if row.get('certificate'):
                    try:
                        from cryptography import x509 as _x509
                        cert = _x509.load_pem_x509_certificate(row['certificate'].encode())
                        try:
                            cert_subject = cert.subject.get_attributes_for_oid(
                                _x509.oid.NameOID.COMMON_NAME)[0].value
                        except Exception:
                            cert_subject = str(cert.subject)
                        cert_not_after = cert.not_valid_after_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
                    except Exception:
                        pass
                result.append({
                    'id':                      row['id'],
                    'name':                    row['name'],
                    'ca_id':                   row['ca_id'],
                    'ca_name':                 row.get('ca_name'),
                    'issuer_ski':              row['issuer_ski'],
                    'response_validity_hours': row.get('response_validity_hours') or (row['response_validity'] * 24),
                    'nonce_policy':            row.get('nonce_policy') or 'optional',
                    'include_cert_in_response': bool(row.get('include_cert_in_response', True)),
                    'responder_id_encoding':   row.get('responder_id_encoding') or 'hash',
                    'hash_algorithm':          row.get('hash_algorithm') or 'sha1',
                    'cert_subject':            cert_subject,
                    'cert_not_after':          cert_not_after,
                })
            return result
        except mysql.connector.Error as e:
            logger.error(f"Database error: {e}")
            return []
        finally:
            if 'cursor' in locals():
                cursor.close()


    def get_ocsp_responder_by_id(self, responder_id: int):
        """Returns a single responder row dict (same shape as get_ocsp_responders_list)."""
        rows = self.get_ocsp_responders_list()
        for row in rows:
            if row['id'] == responder_id:
                return row
        return None


    def update_ocsp_responder_settings(self, responder_id: int, settings: dict):
        """Update the configurable settings for an OCSP responder."""
        allowed = {
            'name', 'response_validity_hours', 'nonce_policy',
            'include_cert_in_response', 'responder_id_encoding', 'hash_algorithm',
        }
        updates = {k: v for k, v in settings.items() if k in allowed}
        if not updates:
            return
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            set_clause = ', '.join(f"{k} = %s" for k in updates)
            values = list(updates.values()) + [responder_id]
            cursor.execute(
                f"UPDATE OCSPResponders SET {set_clause} WHERE id = %s",
                values
            )
            self._local.connection.commit()
            logger.info(f"OCSP responder id={responder_id} settings updated: {list(updates.keys())}")
        except mysql.connector.Error as e:
            logger.error(f"Database error updating OCSP responder: {e}")
            raise
        finally:
            if 'cursor' in locals():
                cursor.close()


    def delete_ocsp_responder(self, responder_id: int):
        """Delete an OCSP responder row by ID."""
        try:
            db_name = self.__config["database"]
            cursor = self._local.connection.cursor(buffered=True)
            cursor.execute(f"USE {db_name}")
            cursor.execute("DELETE FROM OCSPResponders WHERE id = %s", (responder_id,))
            self._local.connection.commit()
            logger.info(f"OCSP responder id={responder_id} deleted")
        except mysql.connector.Error as e:
            logger.error(f"Database error deleting OCSP responder: {e}")
            raise
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


    def insert_certificate(self, pem_certificate: bytes, ca_id: int, template_id: int,
                           private_key_reference: int = None, is_self_signed: bool = False):
        """
        Inserts a certificate record into the Certificates table.

        :param pem_certificate: Certificate in PEM format (string)
        :param ca_id: The CA ID related to this certificate. Pass ``None`` for
                      self-signed certificates.
        :param template_id: The certificate template ID
        :param private_key_reference: (Optional) Reference to the private key ID
        :param is_self_signed: When True, the certificate's subject is also its
                               issuer and it was signed by its own private key.
                               Recorded as a marker so the certificate list can
                               render the distinction without a JOIN.
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
                    not_before, not_after, public_key, private_key_reference,
                    is_self_signed, certificate_data, fingerprint
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                bool(is_self_signed),
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
        revoked_at = datetime.now(timezone.utc)

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

    def migrate_schema(self):
        """
        Apply idempotent schema migrations to an existing database.

        Safe to call on every startup. Each migration checks current schema
        state via INFORMATION_SCHEMA before applying, so re-runs are no-ops.
        Tolerates a missing database or table (e.g. before reset_pki has
        ever been run) by logging and returning silently.
        """
        try:
            with self.connection():
                db_name = self.__config["database"]
                cursor = self._local.connection.cursor(buffered=True)

                # Bail out silently if the database hasn't been created yet.
                cursor.execute(
                    "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = %s",
                    (db_name,)
                )
                if cursor.fetchone() is None:
                    cursor.close()
                    logger.info(f"migrate_schema: database '{db_name}' does not exist yet; skipping")
                    return

                cursor.execute(f"USE {db_name}")

                # Also bail out if the schema exists but is empty (pre-reset_pki
                # state — e.g. first run inside Docker, where MariaDB creates the
                # empty database from MARIADB_DATABASE before reset_pki has built
                # any tables). create_database() will produce the modern schema
                # directly, so migrations have nothing to upgrade.
                cursor.execute(
                    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'CertificationAuthorities'",
                    (db_name,)
                )
                if cursor.fetchone()[0] == 0:
                    cursor.close()
                    logger.info(f"migrate_schema: schema '{db_name}' is empty; skipping (reset_pki will build the modern schema)")
                    return

                # Migration: add CertificationAuthorities.key_owned (introduced when
                # CAs gained support for binding to a pre-existing KMS key).
                cursor.execute(
                    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'CertificationAuthorities' "
                    "AND COLUMN_NAME = 'key_owned'",
                    (db_name,)
                )
                row = cursor.fetchone()
                if row is not None and row[0] == 0:
                    logger.info("migrate_schema: adding CertificationAuthorities.key_owned")
                    cursor.execute(
                        "ALTER TABLE CertificationAuthorities "
                        "ADD COLUMN key_owned BOOLEAN NOT NULL DEFAULT TRUE "
                        "AFTER private_key_reference"
                    )
                    self._local.connection.commit()

                # ── KMS Phase 0.1 — crypto provider model scaffolding ────────────
                # See doc/kms-specs.md §3-4 for the design.
                self._migrate_create_crypto_providers(cursor, db_name)
                self._migrate_extend_keystorage_for_providers(cursor, db_name)
                self._migrate_seed_default_provider(cursor)
                self._migrate_backfill_keystorage_provider_id(cursor)

                # ── KMS Phase 0.2 — encrypt-at-rest software keys ────────────────
                # See doc/kms-specs.md §6-7 for the design.
                self._migrate_encrypt_software_keys(cursor)

                # ── KMS Phase 0.4 — seed the SoftHSM2 dev provider ───────────────
                # Gated on env var so manual installs that don't have SoftHSM
                # don't get a phantom provider row.
                self._migrate_seed_softhsm_provider(cursor)

                # ── Functional improvement: self-signed certificates ─────────────
                # Adds Certificates.is_self_signed so the UI / API can show the
                # distinction without a JOIN gymnastic. See roadmap.md §8.
                self._migrate_certificates_is_self_signed(cursor, db_name)

                cursor.close()
        except mysql.connector.Error as err:
            logger.error(f"Schema migration failed: {err}")
            raise


    # ── KMS provider-model migrations (Phase 0.1) ─────────────────────────────

    def _migrate_create_crypto_providers(self, cursor, db_name):
        """Create the CryptoProviders table on existing installs if missing."""
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'CryptoProviders'",
            (db_name,)
        )
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: creating CryptoProviders table")
            cursor.execute("""
                CREATE TABLE CryptoProviders (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    label VARCHAR(255) NOT NULL UNIQUE,
                    kind ENUM('software', 'pkcs11') NOT NULL,
                    module_path VARCHAR(1024),
                    slot_label VARCHAR(255),
                    auth_kind ENUM('pin', 'luna_role', 'yubihsm_authkey') NOT NULL DEFAULT 'pin',
                    auto_activate BOOLEAN NOT NULL DEFAULT FALSE,
                    auth_secret_ref VARCHAR(512) NOT NULL,
                    auth_secret_blob VARBINARY(1024),
                    extra_json JSON NOT NULL,
                    description TEXT,
                    is_default BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            self._local.connection.commit()

    def _migrate_extend_keystorage_for_providers(self, cursor, db_name):
        """Extend KeyStorage with provider_id, label, and the 'Symmetric' enum value.

        Each step is independently checked so re-runs are no-ops.
        """
        # provider_id column
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'KeyStorage' "
            "AND COLUMN_NAME = 'provider_id'",
            (db_name,)
        )
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: adding KeyStorage.provider_id")
            cursor.execute(
                "ALTER TABLE KeyStorage ADD COLUMN provider_id INT AFTER certificate_id"
            )
            self._local.connection.commit()

        # label column
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'KeyStorage' "
            "AND COLUMN_NAME = 'label'",
            (db_name,)
        )
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: adding KeyStorage.label")
            cursor.execute(
                "ALTER TABLE KeyStorage ADD COLUMN label VARCHAR(255) AFTER public_key"
            )
            self._local.connection.commit()

        # FK to CryptoProviders — only add if both column and target table exist
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'KeyStorage' "
            "AND CONSTRAINT_NAME = 'fk_keystorage_provider_id'",
            (db_name,)
        )
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: adding fk_keystorage_provider_id")
            cursor.execute(
                "ALTER TABLE KeyStorage "
                "ADD CONSTRAINT fk_keystorage_provider_id "
                "FOREIGN KEY (provider_id) REFERENCES CryptoProviders(id)"
            )
            self._local.connection.commit()

        # Extend storage_type ENUM with values added since v1 of the schema.
        # Each addition is checked independently so re-runs are no-ops and
        # an upgrade from an in-between version still picks up what it needs.
        cursor.execute(
            "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'KeyStorage' "
            "AND COLUMN_NAME = 'storage_type'",
            (db_name,)
        )
        row = cursor.fetchone()
        current_type = (row[0] if row else "") or ""
        wanted_values = ["Encrypted", "Plain", "HSM", "Symmetric", "PassphraseEncrypted"]
        missing = [v for v in wanted_values if f"'{v}'" not in current_type]
        if missing:
            logger.info(
                "migrate_schema: extending KeyStorage.storage_type ENUM with "
                f"{missing}"
            )
            cursor.execute(
                "ALTER TABLE KeyStorage MODIFY COLUMN storage_type "
                "ENUM('Encrypted', 'Plain', 'HSM', 'Symmetric', 'PassphraseEncrypted') NOT NULL"
            )
            self._local.connection.commit()

        # KeyStorage.key_owned (introduced when import_pkcs11_key landed,
        # parallel to CertificationAuthorities.key_owned). Distinguishes
        # keys pyPKI generated (deletion cascades to the on-token objects)
        # from keys an operator imported (deletion is a pyPKI-side
        # registration removal only, the on-token objects are preserved).
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'KeyStorage' "
            "AND COLUMN_NAME = 'key_owned'",
            (db_name,)
        )
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: adding KeyStorage.key_owned")
            cursor.execute(
                "ALTER TABLE KeyStorage ADD COLUMN key_owned BOOLEAN NOT NULL "
                "DEFAULT TRUE AFTER storage_type"
            )
            # Pre-existing HSM rows came in via hand-crafted SQL (per the
            # gap analysis pre-Phase-5) — pyPKI didn't generate them and
            # has no claim on the on-token objects. Default them to FALSE
            # so a subsequent delete_key doesn't unilaterally destroy on-
            # token material the operator created out-of-band.
            cursor.execute(
                "UPDATE KeyStorage SET key_owned = FALSE "
                "WHERE storage_type = 'HSM'"
            )
            self._local.connection.commit()

    def _migrate_seed_default_provider(self, cursor):
        """Seed the software-default provider on an existing install if no provider
        is marked as default. Idempotent."""
        cursor.execute("SELECT COUNT(*) FROM CryptoProviders WHERE is_default = TRUE")
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: seeding software-default provider")
            cursor.execute(
                "INSERT INTO CryptoProviders ("
                "    label, kind, auth_kind, auto_activate, auth_secret_ref, "
                "    extra_json, is_default, description"
                ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    'software-default', 'software', 'pin', True,
                    'env:HSM_PIN_KEK', '{}', True,
                    'Default software cryptotoken. Encrypts software keys at rest '
                    'under the KEK derived from HSM_PIN_KEK. Created automatically '
                    'on install.'
                )
            )
            self._local.connection.commit()

    def _migrate_backfill_keystorage_provider_id(self, cursor):
        """Set provider_id on existing software (Plain) KeyStorage rows that lack one.
        HSM rows are intentionally skipped here — they will be assigned to a pkcs11
        provider in a later migration step (Phase 0.4)."""
        cursor.execute(
            "SELECT id FROM CryptoProviders WHERE is_default = TRUE LIMIT 1"
        )
        row = cursor.fetchone()
        if row is None:
            # No default provider — nothing to backfill against.
            return
        default_provider_id = row[0]
        cursor.execute(
            "UPDATE KeyStorage SET provider_id = %s "
            "WHERE provider_id IS NULL "
            "AND storage_type IN ('Plain', 'Encrypted', 'Symmetric')",
            (default_provider_id,)
        )
        if cursor.rowcount > 0:
            logger.info(
                f"migrate_schema: backfilled provider_id={default_provider_id} on "
                f"{cursor.rowcount} software KeyStorage rows"
            )
            self._local.connection.commit()

    def _migrate_encrypt_software_keys(self, cursor):
        """
        Re-encrypt existing software ``KeyStorage`` rows under their
        provider's KEK so the ``private_key`` column never contains
        plaintext PEM.

        Picks up two kinds of rows:
        - ``storage_type='Plain'`` (the obvious case)
        - ``storage_type='Encrypted'`` whose ``private_key`` column actually
          holds plaintext PEM (Gap 10 legacy mislabel — pre-Phase-0 pypki
          had ``'Encrypted'`` as an enum value but no decrypt path).

        Skips silently if ``HSM_PIN_KEK`` is unavailable: this keeps the
        app bootable on a misconfigured deployment so the operator can fix
        the env var and restart. The runtime ``SoftwareBackend.load_key``
        path tolerates the legacy state with a warning, so signing keeps
        working in the meantime.
        """
        from .key_encryption import (
            resolve_provider_secret, derive_kek, encrypt_pem, KEKUnavailable
        )

        cursor.execute(
            "SELECT id, provider_id, key_type, private_key, storage_type "
            "FROM KeyStorage "
            "WHERE private_key IS NOT NULL AND provider_id IS NOT NULL "
            "AND storage_type IN ('Plain', 'Encrypted') "
            "AND (key_type LIKE 'RSA-%%' OR key_type LIKE 'ECDSA-%%' "
            "     OR key_type = 'Ed25519')"
        )
        candidates = cursor.fetchall()
        # Only rows that are actually plaintext-PEM need encrypting.
        rows = []
        for r in candidates:
            key_id, provider_id, key_type, blob, storage_type = r
            blob_str = blob.decode("utf-8", "ignore") if isinstance(blob, (bytes, bytearray)) else blob
            if storage_type == "Plain" or (
                storage_type == "Encrypted" and isinstance(blob_str, str)
                and blob_str.lstrip().startswith("-----BEGIN ")
            ):
                rows.append(r)
        if not rows:
            return

        # Group by provider so we resolve each KEK once.
        by_provider: dict = {}
        for r in rows:
            by_provider.setdefault(r[1], []).append(r)

        # Fetch all relevant provider records up front.
        providers: dict = {}
        for pid in by_provider:
            cursor.execute("SELECT * FROM CryptoProviders WHERE id = %s", (pid,))
            cols = [d[0] for d in cursor.description]
            prec_row = cursor.fetchone()
            providers[pid] = dict(zip(cols, prec_row)) if prec_row else None

        converted = 0
        deferred = 0
        for provider_id, group_rows in by_provider.items():
            provider = providers.get(provider_id)
            if not provider:
                logger.warning(
                    f"migrate_schema: KeyStorage rows reference missing "
                    f"provider_id={provider_id}; leaving them as-is."
                )
                continue
            try:
                pin = resolve_provider_secret(provider)
                kek = derive_kek(pin, provider_id)
            except KEKUnavailable as e:
                # Don't block app startup. The runtime load path tolerates
                # plaintext-PEM-in-Encrypted rows (Gap 10 legacy) and Plain
                # rows have always been tolerated.
                deferred += len(group_rows)
                logger.warning(
                    f"migrate_schema: deferring encryption of {len(group_rows)} "
                    f"row(s) on provider id={provider_id} "
                    f"('{provider.get('label')}'): {e} — set the secret and "
                    f"restart to migrate."
                )
                continue
            for row in group_rows:
                key_id, _, _, pem, _ = row
                pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
                blob = encrypt_pem(pem_bytes, kek)
                cursor.execute(
                    "UPDATE KeyStorage SET private_key = %s, storage_type = 'Encrypted' "
                    "WHERE id = %s",
                    (blob, key_id)
                )
                converted += 1

        if converted > 0:
            logger.info(
                f"migrate_schema: encrypted-at-rest {converted} software key row(s) "
                f"under per-provider KEKs"
                + (f" ({deferred} deferred)" if deferred else "")
            )
            self._local.connection.commit()
        elif deferred > 0:
            logger.warning(
                f"migrate_schema: {deferred} software key row(s) await encryption "
                f"(HSM_PIN_KEK or other secret unavailable)."
            )

    def _migrate_certificates_is_self_signed(self, cursor, db_name):
        """
        Add ``Certificates.is_self_signed`` on existing installs. Idempotent
        — checks INFORMATION_SCHEMA before issuing the ALTER. Existing
        rows default to FALSE, which matches the historical reality (only
        CA-issued certificates existed before this column).
        """
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'Certificates' "
            "AND COLUMN_NAME = 'is_self_signed'",
            (db_name,)
        )
        row = cursor.fetchone()
        if row is not None and row[0] == 0:
            logger.info("migrate_schema: adding Certificates.is_self_signed")
            cursor.execute(
                "ALTER TABLE Certificates ADD COLUMN is_self_signed BOOLEAN "
                "NOT NULL DEFAULT FALSE AFTER private_key_reference"
            )
            self._local.connection.commit()


    def _migrate_seed_softhsm_provider(self, cursor):
        """
        Idempotently seed a 'softhsm-dev' pkcs11 provider when the operator
        has opted in via PYPKI_SEED_SOFTHSM_PROVIDER=true and the relevant
        PKCS11_* env vars are present.

        Used in the Docker dev container (which already installs SoftHSM2,
        initialises a token, and sets PKCS11_MODULE / PKCS11_TOKEN_LABEL /
        PKCS11_PIN) to make the SoftHSM provider show up in the management
        UI / API as a first-class citizen.

        Skipped silently otherwise — manual installs without SoftHSM stay
        with just the seeded software-default provider.
        """
        import os

        if (os.environ.get("PYPKI_SEED_SOFTHSM_PROVIDER") or "").lower() not in {"1", "true", "yes"}:
            return

        # Already seeded?
        cursor.execute(
            "SELECT id FROM CryptoProviders WHERE label = %s",
            ("softhsm-dev",)
        )
        if cursor.fetchone() is not None:
            return

        module_path = os.environ.get("PKCS11_MODULE")
        slot_label = os.environ.get("PKCS11_TOKEN_LABEL")
        pin_env = "PKCS11_PIN"  # the env var from which the provider resolves its PIN

        if not module_path or not slot_label:
            logger.warning(
                "migrate_schema: PYPKI_SEED_SOFTHSM_PROVIDER=true but "
                "PKCS11_MODULE / PKCS11_TOKEN_LABEL not set; skipping seed."
            )
            return

        if not os.path.exists(module_path):
            logger.warning(
                f"migrate_schema: PKCS11_MODULE='{module_path}' does not exist on disk; "
                "skipping softhsm-dev seed."
            )
            return

        logger.info(
            f"migrate_schema: seeding softhsm-dev provider "
            f"(module_path={module_path}, slot_label={slot_label})"
        )
        cursor.execute(
            "INSERT INTO CryptoProviders ("
            "    label, kind, module_path, slot_label, auth_kind, auto_activate, "
            "    auth_secret_ref, extra_json, is_default, description"
            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                'softhsm-dev', 'pkcs11', module_path, slot_label, 'pin', True,
                f'env:{pin_env}', '{}', False,
                'SoftHSM2 development PKCS#11 provider seeded automatically when '
                'PYPKI_SEED_SOFTHSM_PROVIDER=true. Token and PIN come from the '
                'PKCS11_* environment variables.'
            )
        )
        self._local.connection.commit()


    def create_database(self):
        db_name = self.__config["database"]

        if self._local.connection:
            cursor = self._local.connection.cursor()

            cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")  # Drop the database if it exists
            cursor.execute(f"CREATE DATABASE {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")

            # Now connect to the actual database
            self._local.connection.database = db_name

            # STEP 1: Create the tables without foreign keys

            # Use the specified database
            cursor.execute(f"USE {db_name}")

            # SQL for creating the tables without foreign keys
            tables_without_fk = {
                "CryptoProviders": """
                    CREATE TABLE IF NOT EXISTS CryptoProviders (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        label VARCHAR(255) NOT NULL UNIQUE,
                        kind ENUM('software', 'pkcs11') NOT NULL,
                        module_path VARCHAR(1024),
                        slot_label VARCHAR(255),
                        auth_kind ENUM('pin', 'luna_role', 'yubihsm_authkey') NOT NULL DEFAULT 'pin',
                        auto_activate BOOLEAN NOT NULL DEFAULT FALSE,
                        auth_secret_ref VARCHAR(512) NOT NULL,
                        auth_secret_blob VARBINARY(1024),
                        extra_json JSON NOT NULL,
                        description TEXT,
                        is_default BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    );
                """,
                "KeyStorage": """
                    CREATE TABLE IF NOT EXISTS KeyStorage (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        certificate_id INT,
                        provider_id INT,
                        key_type VARCHAR(64),
                        private_key TEXT,
                        public_key TEXT,
                        label VARCHAR(255),
                        storage_type ENUM('Encrypted', 'Plain', 'HSM', 'Symmetric', 'PassphraseEncrypted') NOT NULL,
                        key_owned BOOLEAN NOT NULL DEFAULT TRUE,
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
                        key_owned BOOLEAN NOT NULL DEFAULT TRUE,
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
                        is_self_signed BOOLEAN NOT NULL DEFAULT FALSE,
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
                        response_validity_hours INT DEFAULT 24,
                        nonce_policy ENUM('optional','required','disabled') DEFAULT 'optional',
                        include_cert_in_response BOOLEAN DEFAULT TRUE,
                        responder_id_encoding ENUM('hash','name') DEFAULT 'hash',
                        hash_algorithm ENUM('sha1','sha256') DEFAULT 'sha1',
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
                """,
                """
                ALTER TABLE KeyStorage
                ADD CONSTRAINT fk_keystorage_provider_id
                FOREIGN KEY (provider_id) REFERENCES CryptoProviders(id);
                """
            ]

            # Add foreign keys to the tables
            for fk_statement in foreign_keys:
                logger.info(f"Adding foreign key: {fk_statement}")
                cursor.execute(fk_statement)

            # Seed the default software crypto provider. New software keys default
            # to this provider unless the operator explicitly creates another one.
            # See doc/kms-specs.md §3-4 for the provider model.
            logger.info("Seeding default software provider")
            cursor.execute(
                "INSERT INTO CryptoProviders ("
                "    label, kind, auth_kind, auto_activate, auth_secret_ref, "
                "    extra_json, is_default, description"
                ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    'software-default', 'software', 'pin', True,
                    'env:HSM_PIN_KEK', '{}', True,
                    'Default software cryptotoken. Encrypts software keys at rest '
                    'under the KEK derived from HSM_PIN_KEK. Created automatically '
                    'on install.'
                )
            )

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
