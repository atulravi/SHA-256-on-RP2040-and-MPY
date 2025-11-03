# SHA-256 Throughput Analysis for RP2040 Software Implementation
from sha256_micropython import SHA256, sha256, sha256_hex
import time

def calculate_theoretical_throughput():
    print("SHA-256 Throughput Measurement\n")
    
    # Test with various block sizes
    test_sizes = [64, 512, 1024, 4096, 8192]  # bytes
    
    print("Testing throughput with different data sizes:\n")
    
    for size in test_sizes:
        message = "x" * size
        message_bytes = len(message.encode('utf-8'))
        
        # Run multiple iterations for accuracy
        iterations = 10 if size < 1024 else 5
        
        start = time.ticks_us()
        for _ in range(iterations):
            hash_result = sha256_hex(message)
        end = time.ticks_us()
        
        total_elapsed_us = time.ticks_diff(end, start)
        avg_elapsed_us = total_elapsed_us / iterations
        avg_elapsed_s = avg_elapsed_us / 1000000.0
        
        # Calculate throughput
        throughput_bytes_per_sec = message_bytes / avg_elapsed_s
        throughput_kb_per_sec = throughput_bytes_per_sec / 1024
        throughput_mb_per_sec = throughput_kb_per_sec / 1024
        
        # Calculate blocks processed (SHA-256 uses 512-bit/64-byte blocks)
        num_blocks = (message_bytes + 63) // 64  # Round up
        cycles_per_byte = (125000000 * avg_elapsed_s) / message_bytes  # RP2040 @ 125MHz
        
        print(f"Size: {message_bytes:5d} bytes ({num_blocks:3d} blocks)")
        print(f"  Time: {avg_elapsed_us:8.0f} us")
        print(f"  Throughput: {throughput_mb_per_sec:6.3f} MB/s ({throughput_kb_per_sec:7.2f} KB/s)")
        print(f"  Cycles/byte: {cycles_per_byte:.1f} @ 125 MHz")
        print()
    

def single_block_analysis():
    print("\nSingle Block (64 bytes) Analysis \n")
    
    # Exactly one block
    message = "a" * 55  # After padding, this becomes exactly 64 bytes (one block)
    message_bytes = len(message.encode('utf-8'))
    
    iterations = 100
    start = time.ticks_us()
    for _ in range(iterations):
        hash_result = sha256_hex(message)
    end = time.ticks_us()
    
    avg_time_us = time.ticks_diff(end, start) / iterations
    avg_time_ms = avg_time_us / 1000.0
    
    # RP2040 runs at 125 MHz
    cycles_at_125mhz = (avg_time_us / 1000000) * 125000000
    
    print(f"Message size: {message_bytes} bytes (1 block after padding)")
    print(f"Average time: {avg_time_us:.1f} us ({avg_time_ms:.3f} ms)")
    print(f"Estimated cycles @ 125 MHz: {cycles_at_125mhz:.0f}")
    print(f"\nRP2350 Hardware: 121 cycles per block")
    print(f"RP2040 Software: ~{cycles_at_125mhz:.0f} cycles per block")
    print(f"Slowdown factor: ~{cycles_at_125mhz/121:.1f}x")

# Run tests
calculate_theoretical_throughput()
single_block_analysis()