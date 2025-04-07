import PyKCS11

# Initialize the PKCS#11 library
pkcs11 = PyKCS11.PyKCS11Lib()

# Load the PKCS#11 module (change the path if needed)
pkcs11.load('/usr/local/lib/pkcs11/libeTPkcs11.dylib')  # Replace with the actual path to your PKCS#11 library

# Get a list of all slots
slots = pkcs11.getSlotList()

# Check for tokens in the slots
if slots:
    # Open a session with the first token in the list
    slot = slots[0]  # Assuming the token is in the first slot
    session = pkcs11.openSession(slot)

    # Get the list of supported mechanisms for the slot
    mechanisms = pkcs11.getMechanismList(slot)  # Corrected: Use pkcs11.getMechanismList

    print(mechanisms)

    # Print supported mechanisms
    for mech in mechanisms:
        mech_name = PyKCS11.CKM_MECHANISM_NAME.get(mech, 'Unknown Mechanism')
        print(f"Mechanism: {mech} - {mech_name}")
else:
    print("No tokens found.")
