def generate_certificate(data):
    # Dummy logic to simulate cert generation
    # In a real implementation, integrate with a PKI system or crypto library
    return {"certificate": "GeneratedCertFor" + data.get("name", "unknown")}

def revoke_certificate(data):
    # Dummy logic for cert revocation
    return {"status": "Certificate revoked for " + data.get("name", "unknown")}
