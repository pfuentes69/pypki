"""
Thin PyKCS11 wrapper used by :class:`pypki.backends.PKCS11Backend`.

Scope after Phase 6: session lifecycle only — load the PKCS#11 module,
open and login a session against a labelled token slot, hand the live
``PyKCS11.Session`` to the backend, and tear it all down on close.
Everything semantically interesting (mechanism dispatch, mandatory
CKA_* attributes, generate / find / delete with the right semantics,
reconnect-on-session-invalid, locking) lives in
``pypki/backends/pkcs11.py``.

The legacy methods that previously lived here (``get_token_info``,
``get_certificates``, ``generate_private_key``, etc.) were unused and
have been removed; the eight-method audit is recorded in the Phase 5
review notes.
"""
import PyKCS11

from .log import logger


class PKCS11Helper:
    """PKCS#11 session lifecycle wrapper. Owns one ``PyKCS11.Session``
    for the lifetime of an activation."""

    def __init__(self, lib_path: str):
        """
        Load the PKCS#11 module at ``lib_path``. The path must be supplied
        explicitly — every legitimate caller now sources it from the
        ``CryptoProviders.module_path`` column, and falling back to a
        platform-specific default would silently mask a misconfigured
        provider on a different host.
        """
        if not lib_path:
            raise ValueError(
                "PKCS11Helper: lib_path is required (typically sourced from "
                "CryptoProviders.module_path; see doc/kms-specs.md §4.1)."
            )
        self.__pkcs11 = PyKCS11.PyKCS11Lib()
        self.__pkcs11.load(lib_path)
        self.__session: PyKCS11.Session | None = None

    # ── session lifecycle ────────────────────────────────────────────────────

    def open_session(self, token_password: str, slot_label: str = None) -> PyKCS11.Session:
        """
        Open a session against the slot whose token label matches
        ``slot_label``. When ``slot_label`` is None, fall back to the first
        slot with an initialised token (and log a warning) — preserved for
        legacy callers that pre-date the provider model.

        Matching by ``CK_TOKEN_INFO.label`` is the only stable way to address
        a token: numeric slot ids are not stable across reinitialisations
        (SoftHSM2 randomises them at ``--init-token`` time precisely to force
        this discipline; real HSMs change them across reboots, firmware
        updates, or when partitions are added).
        """
        slots = self.__pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No PKCS#11 tokens found")

        chosen = None
        if slot_label:
            target = slot_label.strip()
            for slot in slots:
                try:
                    info = self.__pkcs11.getTokenInfo(slot)
                except PyKCS11.PyKCS11Error:
                    continue
                if info.label.strip() == target:
                    chosen = slot
                    break
            if chosen is None:
                available = []
                for slot in slots:
                    try:
                        available.append(self.__pkcs11.getTokenInfo(slot).label.strip())
                    except PyKCS11.PyKCS11Error:
                        pass
                raise RuntimeError(
                    f"PKCS#11: no token with label {slot_label!r} found "
                    f"(available labels: {available})"
                )
        else:
            # Skip placeholder slots whose token is not initialised
            # (SoftHSM2 reports a free slot at id 0 alongside initialised
            # tokens) so we land on something usable.
            for slot in slots:
                try:
                    info = self.__pkcs11.getTokenInfo(slot)
                except PyKCS11.PyKCS11Error:
                    continue
                if int(info.flags) & PyKCS11.CKF_TOKEN_INITIALIZED:
                    chosen = slot
                    break
            if chosen is None:
                chosen = slots[0]
            logger.warning(
                "PKCS#11: open_session called without slot_label; falling back "
                f"to slot id={chosen}. Configure CryptoProviders.slot_label to "
                "make this stable across reinitialisations."
            )

        self.__session = self.__pkcs11.openSession(
            chosen, PyKCS11.CKF_RW_SESSION | PyKCS11.CKF_SERIAL_SESSION
        )
        self.__session.login(str(token_password).encode("utf-8"), PyKCS11.CKU_USER)
        return self.__session

    def get_session(self) -> PyKCS11.Session:
        return self.__session

    def close_session(self) -> None:
        if self.__session:
            self.__session.logout()
            self.__session.closeSession()
            self.__session = None
