from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Task 4A: Simulate DH Key Exchange

# Generate DH parameters (shared between Alice and Bob)
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Alice's key pair
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Bob's key pair
bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

# Compute shared secret on both sides
alice_shared_key = alice_private_key.exchange(bob_public_key)
bob_shared_key = bob_private_key.exchange(alice_public_key)

# Convert public keys to PEM format
alice_pub_pem = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

bob_pub_pem = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Save public keys to files
with open("alice_public.pem", "w") as f:
    f.write(alice_pub_pem)

with open("bob_public.pem", "w") as f:
    f.write(bob_pub_pem)

# Print key exchange results
print("Alice's Public Key:")
print(alice_pub_pem)
print("\nBob's Public Key:")
print(bob_pub_pem)
print("\nShared keys match:", alice_shared_key == bob_shared_key)