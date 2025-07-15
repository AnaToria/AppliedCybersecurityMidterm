from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# ========== Task 2A ==========
# Generate ECC private key (prime256v1 = SECP256R1)
private_key = ec.generate_private_key(ec.SECP256R1())

# Save private key to ecc_private.pem
with open("ecc_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Extract and save public key to ecc_public.pem
public_key = private_key.public_key()
with open("ecc_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# ========== Task 2B ==========
# Create message file
message_text = "Elliptic Curves are efficient."
with open("ecc.txt", "w") as f:
    f.write(message_text)

# Read message for signing
message_bytes = message_text.encode()

# Sign the message with the private key
signature = private_key.sign(
    message_bytes,
    ec.ECDSA(hashes.SHA256())
)

# Save signature to file
with open("ecc.sig", "wb") as f:
    f.write(signature)

# Load public key from file for verification
with open("ecc_public.pem", "rb") as f:
    loaded_public_key = serialization.load_pem_public_key(f.read())

# Verify the signature
try:
    loaded_public_key.verify(
        signature,
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    print("Signature is valid.")
except InvalidSignature:
    print("Signature is invalid.")
