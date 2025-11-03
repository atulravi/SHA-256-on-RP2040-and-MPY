import time

# SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def _rotr(x, n):
    """Right rotate a 32-bit integer"""
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def _ch(x, y, z):
    """SHA-256 Ch function"""
    return (x & y) ^ (~x & z)

def _maj(x, y, z):
    """SHA-256 Maj function"""
    return (x & y) ^ (x & z) ^ (y & z)

def _ep0(x):
    """SHA-256 Sigma0 function"""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

def _ep1(x):
    """SHA-256 Sigma1 function"""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

def _sig0(x):
    """SHA-256 sigma0 function"""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)

def _sig1(x):
    """SHA-256 sigma1 function"""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


class SHA256:
    """SHA-256 hash implementation"""
    
    def __init__(self):
        """Initialize SHA-256 context"""
        # Initialize hash state (first 32 bits of fractional parts of square roots of first 8 primes)
        self.state = [
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        ]
        self.buffer = bytearray()
        self.bit_count = 0
    
    def _transform(self, block):
        """Process a single 512-bit block"""
        # Prepare message schedule
        W = [0] * 64
        
        # First 16 words are the message block
        for i in range(16):
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | \
                   (block[i * 4 + 2] << 8) | block[i * 4 + 3]
        
        # Extend the first 16 words into the remaining 48 words
        for i in range(16, 64):
            W[i] = (_sig1(W[i - 2]) + W[i - 7] + _sig0(W[i - 15]) + W[i - 16]) & 0xffffffff
        
        # Initialize working variables
        a, b, c, d, e, f, g, h = self.state
        
        # Main compression loop
        for i in range(64):
            t1 = (h + _ep1(e) + _ch(e, f, g) + K[i] + W[i]) & 0xffffffff
            t2 = (_ep0(a) + _maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        
        # Add compressed chunk to current hash value
        self.state[0] = (self.state[0] + a) & 0xffffffff
        self.state[1] = (self.state[1] + b) & 0xffffffff
        self.state[2] = (self.state[2] + c) & 0xffffffff
        self.state[3] = (self.state[3] + d) & 0xffffffff
        self.state[4] = (self.state[4] + e) & 0xffffffff
        self.state[5] = (self.state[5] + f) & 0xffffffff
        self.state[6] = (self.state[6] + g) & 0xffffffff
        self.state[7] = (self.state[7] + h) & 0xffffffff
    
    def update(self, data):
        """
        Update the hash with new data
        
        Args:
            data: bytes or bytearray to hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self.buffer.extend(data)
        self.bit_count += len(data) * 8
        
        # Process complete 64-byte blocks
        while len(self.buffer) >= 64:
            self._transform(self.buffer[:64])
            self.buffer = self.buffer[64:]
    
    def digest(self):
        """
        Finalize the hash and return the digest
        
        Returns:
            bytes: 32-byte hash digest
        """
        # Make a copy to preserve state for multiple digest calls
        final_buffer = bytearray(self.buffer)
        final_bit_count = self.bit_count
        
        # Pad with 0x80 followed by zeros
        final_buffer.append(0x80)
        
        # If we don't have room for the length, pad to 64 bytes and process
        if len(final_buffer) > 56:
            while len(final_buffer) < 64:
                final_buffer.append(0x00)
            self._transform(final_buffer)
            final_buffer = bytearray()
        
        # Pad with zeros until we have 56 bytes
        while len(final_buffer) < 56:
            final_buffer.append(0x00)
        
        # Append length in bits as 64-bit big-endian
        for i in range(8):
            final_buffer.append((final_bit_count >> (56 - i * 8)) & 0xff)
        
        # Process final block
        self._transform(final_buffer)
        
        # Produce final hash value (big-endian)
        digest = bytearray()
        for word in self.state:
            digest.append((word >> 24) & 0xff)
            digest.append((word >> 16) & 0xff)
            digest.append((word >> 8) & 0xff)
            digest.append(word & 0xff)
        
        return bytes(digest)
    
    def hexdigest(self):
        """
        Return the digest as a hexadecimal string
        
        Returns:
            str: 64-character hexadecimal hash
        """
        digest = self.digest()
        return ''.join('%02x' % b for b in digest)


def sha256(data):
    """
    Convenience function to hash data in one call
    
    Args:
        data: bytes, bytearray, or string to hash
    
    Returns:
        bytes: 32-byte hash digest
    """
    hasher = SHA256()
    hasher.update(data)
    return hasher.digest()


def sha256_hex(data):
    """
    Convenience function to hash data and return hex string
    
    Args:
        data: bytes, bytearray, or string to hash
    
    Returns:
        str: 64-character hexadecimal hash
    """
    hasher = SHA256()
    hasher.update(data)
    return hasher.hexdigest()


def run_tests():
    """Run test vectors to verify implementation"""
    print("\n=== SHA-256 on RP2040 (MicroPython) ===\n")
    
    # Test vectors from NIST
    test_vectors = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ("The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    ]
    
    all_passed = True
    
    for input_str, expected_hash in test_vectors:
        print(f'Input: "{input_str}"')
        print(f'Expected: {expected_hash}')
        
        # Time the operation
        start = time.ticks_us()
        computed_hash = sha256_hex(input_str)
        elapsed = time.ticks_diff(time.ticks_us(), start)
        
        print(f'Computed: {computed_hash}')
        
        if computed_hash == expected_hash:
            print(f'PASS (Time: {elapsed} microseconds)')
        else:
            print('FAIL')
            all_passed = False
        
        print()
    
    if all_passed:
        print("All tests passed!")
    else:
        print("Some tests failed!")
    
    return all_passed


# Example usage
if __name__ == '__main__':
    # Run test vectors
    run_tests()
    
    # Example of incremental hashing
    print("\n=== Incremental Hashing Example ===\n")
    hasher = SHA256()
    hasher.update("Hello, ")
    hasher.update("World!")
    print(f"Hash of 'Hello, World!': {hasher.hexdigest()}")
    
    # Compare with one-shot
    one_shot = sha256_hex("Hello, World!")
    print(f"One-shot hash:          {one_shot}")
    print(f"Match: {hasher.hexdigest() == one_shot}")
