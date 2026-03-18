from cryptography import x509

class PKITools:
    INFINITE_VALIDITY = -1

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
