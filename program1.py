from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import sys

# Step 1: Take the message input from the user
message = input("Enter the message: ").encode()

# Step 2: Generate RSA key pair (private and public keys)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Step 3: Compute the SHA-256 hash of the message
digest = hashes.Hash(hashes.SHA256())
digest.update(message)
hashed_message = digest.finalize()

# Step 4: Apply PSS padding to the hash
pss_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# Step 5: Sign the padded hash with the private key
signature = private_key.sign(hashed_message, pss_padding, hashes.SHA256())

# Step 6: Serialize the public key to PEM format
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Step 7: Print the original content, digital signature, and serialized public key
print(f"Original content: {message.decode()}")
print(f"Digital signature: {signature.hex()}")
print(f"Serialized public key (PEM):\n{pem_public_key.decode()}")
