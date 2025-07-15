import os
import hashlib
import hmac

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# ========== Task 3A: SHA-256 Hash ==========
# Create the file
original_text = "Never trust, always verify."
with open("data.txt", "w") as f:
    f.write(original_text)

# Compute SHA-256 hash
with open("data.txt", "rb") as f:
    file_bytes = f.read()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

print("Task 3A - SHA-256 Hash:")
print(sha256_hash)
print()

# ========== Task 3B: HMAC using SHA-256 ==========
secret_key = b"secretkey123"
hmac_value = hmac.new(secret_key, file_bytes, hashlib.sha256).hexdigest()

print("Task 3B - HMAC (SHA-256 with key 'secretkey123'):")
print(hmac_value)
print()

# Save original HMAC for Task 3C comparison
with open("original.hmac", "w") as f:
    f.write(hmac_value)

# ========== Task 3C: Modify file and check HMAC ==========
# Modify one character
tampered_text = "Never trust, always verifx."
with open("data.txt", "w") as f:
    f.write(tampered_text)

# Recompute HMAC after tampering
with open("data.txt", "rb") as f:
    tampered_bytes = f.read()
    tampered_hmac = hmac.new(secret_key, tampered_bytes, hashlib.sha256).hexdigest()

print("Task 3C - Tampered HMAC:")
print(tampered_hmac)
print()

# Explain
if tampered_hmac != hmac_value:
    print("HMAC mismatch detected.")
    print("Explanation: The HMAC changed after even a 1-character modification. This proves HMAC protects both data integrity and authenticity.")
else:
    print("HMAC did not change (unexpected).")
