#Speed test
from sha256_micropython import SHA256, sha256, sha256_hex
import time


def speedtest():
    print("Speed Test:")
    
    test_sizes = [16, 64, 256, 1024]  # bytes
    
    for size in test_sizes:
        data = "x" * size
        
        # Time the hashing
        start = time.ticks_us()
        _ = sha256(data)
        elapsed = time.ticks_diff(time.ticks_us(), start)
        
        throughput = (size / elapsed) * 1000000 / 1024  # KB/s
        print(f"{size:4d} bytes: {elapsed:6d} us ({throughput:.1f} KB/s)")
        
speedtest()