#Data Hashing demo

from sha256_micropython import SHA256, sha256, sha256_hex
import time

def datahash():
    print("Simple Hash")
    message = "GO"
    hash_result = sha256_hex(message)
    print(f"Message: {message}")
    print(f"SHA-256: {hash_result}")

datahash()