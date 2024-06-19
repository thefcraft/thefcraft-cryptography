# Not that faster but it do its work...

import struct

def preprocess(data):
    length_bits = len(data) * 8 # Initial length of the message in bits
    data += b'\x80' # b'\x80' is hexadecimal for binary '10000000'
    # Append '0' bits until length is 448 bits modulo 512
    while len(data) % 64 != 56: # while bit_len(data) % 512 != 448:
        data += b'\x00'
    # Append the length of the original message as a 64-bit integer
    data += length_bits.to_bytes(8, byteorder='big')
    return data

# & 0xFFFFFFFF Ensures that the result is masked to 32 bits, handling any overflow that may occur during the operations.

def rotate(x, n):
    """clockwise rotate a 32-bit integer to n positions"""
    # `x >> n` shifts the bits of `x` to the right by `n` positions. This moves the bits that fall off the right end back to the left end.
    # `x << (32 - n)` shifts the bits of `x` to the left by `(32 - n)` positions. This moves the bits that fall off the left end back to the right end.
    # `|` combines the results of the right shift and left shift operations.
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def s0(x):
    return (rotate(x, 7) ^ rotate(x, 18) ^ x>>3) & 0xFFFFFFFF
def s1(x): 
    return (rotate(x, 17) ^ rotate(x, 19) ^ x>>10) & 0xFFFFFFFF

def sigma0(x):
    return (rotate(x, 2) ^ rotate(x, 13) ^ rotate(x, 22)) & 0xFFFFFFFF
def sigma1(x):
    return (rotate(x, 6) ^ rotate(x, 11) ^ rotate(x, 25)) & 0xFFFFFFFF

def Ch(e, f, g):
    # take bit from f if e is one else take bit from g
    # e = 0b01010001_00001110_01010010_01111111
    # f = 0b10011011_00000101_01101000_10001100
    # g = 0b00011111_10000011_11011001_10101011
    # out 0b00011111_10000101_11001001_10001100
    # format(Ch(e,f,g), '032b')
    return (e & f) ^ (~e & g)

def Maj(a, b, c):
    # if the majority of the bits at that position are 1, the result bit will be 1
    # a = 0b01010001_00001110_01010010_01111111
    # b = 0b10011011_00000101_01101000_10001100
    # c = 0b00011111_10000011_11011001_10101011
    # out 0b00011011_00000111_01011000_10101111
    # format(Maj(a,b,c), '032b')
    return (a & b) ^ (a & c) ^ (b & c)

def chunk_iter(msg, chunk_size=64):
    # Process the message in successive 512-bit chunks
    for i in range(0, len(msg), chunk_size):
        yield msg[i:i+chunk_size]

# Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19
H = [
    H0, H1, H2, H3,
    H4, H5, H6, H7
]
# Initialize array of round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
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


def constant_generator():
    def is_prime(n:int)->bool:
        if n < 2: return False
        if n in (2, 3): return True
        if n % 2 == 0 or n % 3 == 0: return False
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0: return False
            i += 6
        return True
    def first_prime(n:int):
        i = 2
        while n:
            if is_prime(i): 
                yield i
                n-=1
            i+=1

    def sqrt(n:int)->int: return n**(1/2)
    def cbrt(n:int)->int: return n**(1/3)
    def fractionalpart(x:int)->float:
        assert x>=0, "not implemented for negative"
        return x - x//1

    H = []
    K = []
    for p in first_prime(8):
        f = fractionalpart(sqrt(p))
        H.append(int(f * (1 << 32)))
    for p in first_prime(64):
        f = fractionalpart(cbrt(p))
        K.append(int(f * (1 << 32)))
    return H, K

H, K = constant_generator()

def sha256(data):
    h0, h1, h2, h3, h4, h5, h6, h7 = H
        
    data = preprocess(data)
        
    for chunk in chunk_iter(data, chunk_size=64):
        # chunk is a bytes object of length 64
        # M = struct.unpack('>16I', chunk) # M0...M15 
        # slow M = [int.from_bytes(chunk[i:i+4], byteorder='big') for i in range(0, 64, 4)]
        # W = [M[i] for i in range(16)]
        
        W = list(struct.unpack('>16I', chunk)) + [0] * 48
        
        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        for t in range(16, 64):
            # wt = s1(wt-2) + wt-7 + s0(wt-15) + wt-16
            W[t] = (s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]) & 0xFFFFFFFF
            # wt = (s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]) & 0xFFFFFFFF
            # W.append(wt)
            
        # Initialize working variables
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # main loop
        for t in range(64):
            # T1 = h + Σ1(e) + Ch(e, f, g) + K[t] + W[t]
            # T2 = Σ0(a) + Maj(a, b, c)
            T1 = (h + sigma1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
            T2 = (sigma0(a) + Maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF
        
        # computer the intermediate hash     
        h0 = (a + h0) & 0xFFFFFFFF
        h1 = (b + h1) & 0xFFFFFFFF
        h2 = (c + h2) & 0xFFFFFFFF
        h3 = (d + h3) & 0xFFFFFFFF
        h4 = (e + h4) & 0xFFFFFFFF
        h5 = (f + h5) & 0xFFFFFFFF
        h6 = (g + h6) & 0xFFFFFFFF
        h7 = (h + h7) & 0xFFFFFFFF
    
    concatenate_hashes = (h0 << 224) | (h1 << 192) | (h2 << 160) | (h3 << 128) | (h4 << 96) | (h5 << 64) | (h6 << 32) | h7    
    return hex(concatenate_hashes)


if __name__ == "__main__":
    # Example usage:
    with open(r"C:\Users\laksh\OneDrive\Pictures\wallpaperflare.com_wallpaper (14).jpg", 'rb') as f:
        message = f.read()
    # message = b'Hello, world!'
    hashed = sha256(message)
    print("SHA-256 Hash:", hashed[2:])
    import hashlib
    print("SHA-256 Hash:", hashlib.sha256(message).hexdigest())
