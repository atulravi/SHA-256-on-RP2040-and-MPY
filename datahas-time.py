# Data Hashing demo
from sha256_micropython import SHA256, sha256, sha256_hex
import time

def datahash():
    print("Simple Hash")
    message = "GO"
    
    start = time.ticks_us()
    hash_result = sha256_hex(message)
    end = time.ticks_us()
    
    elapsed = time.ticks_diff(end, start)
    elapsed_ms = elapsed / 1000.0
    
    print(f"Message: {message}")
    print(f"SHA-256: {hash_result}")
    print(f"Time: {elapsed} microseconds ({elapsed_ms:.3f} ms)")

datahash()