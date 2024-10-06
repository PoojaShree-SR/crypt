from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Step 1: Replace with the message you want to verify
original_content = b"Enter the message"

# Step 2: Replace with the digital signature to verify
digital_signature = bytes.fromhex("Enter the digital signature")

# Step 3: Replace with the PEM-encoded public key from the signing process
public_key_pem = b"""-----BEGIN PUBLIC KEY-----
Replace this with the PEM public key
-----END PUBLIC KEY-----"""

# Step 4: Load the public key from PEM format
public_key = serialization.load_pem_public_key(public_key_pem)

# Step 5: Verify the digital signature with the public key
try:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(original_content)
    hashed_message = digest.finalize()

    public_key.verify(
        digital_signature,
        hashed_message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Signature is valid.")

# Step 6: Handle exceptions to indicate verification errors
except InvalidSignature:
    print("Signature is invalid.")
