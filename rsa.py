import random, math
from typing import Optional

def is_prime(n:int)->bool:
    # if n<2: return False
    # for i in range(2, math.floor(math.sqrt(n))+1): 
        # if(n % i == 0): return False
    # return True
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True
def prime_number_greater_than(n:int)->int:
    while True:
        if is_prime(n): return n
        n+=1

def gcd(a:int, b:int)->int:
    # The Euclidean algorithm is based on the principle that the GCD of two numbers also divides their difference.
    while b:
        a, b = b, a % b
    return a
def is_coprime(a:int, b:int)->bool:
    return gcd(a, b)==1
def is_integer(n:int)->bool:
    return n%1 == 0

def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y
def modular_inverse(e: int, phi: int) -> int:
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    else:
        return x % phi

def int_to_base255(n: int) -> list:
    if n == 0:
        return [0]
    
    digits = []
    while n:
        digits.append(n % 255)
        n //= 255
    
    return digits[::-1]  # Reverse the list to get the correct order
def base255_to_int(digits: list) -> int:
    n = 0
    for digit in digits:
        n = n * 255 + digit
    
    return n
def int_to_bytes(value, byte_size=255):
    """Convert an integer to a list of bytes, ensuring each byte is within the range 0-255."""
    bytes_list = []
    while value > 0:
        bytes_list.append(value % byte_size)
        value //= byte_size
    return bytes_list[::-1]  # Reverse the list to maintain the correct order

def split_into_chunks(lst, chunk_size=3):
    """Splits a list into chunks of specified size."""
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]

def cryptor_raw(data:int, key:int, n:int)->int:
    assert data < n, "data must be less than n"
    result = 1  # Initialize result
    base = data % n  # Ensure base is in the correct range

    while key > 0:
        # If key is odd, multiply the base with the result
        if key % 2 == 1:
            result = (result * base) % n
        
        # Now key must be even, divide it by 2
        key = key // 2
        base = (base * base) % n  # Square the base and reduce it modulo n

    return result
def cryptor(data:bytearray, key:int, n:int)->bytearray:
    # encoded = [cryptor_raw(base255_to_int(i), key, n) for i in split_into_chunks(data, chunk_size=1)]
    result = []
    for i in data:
        encoded_value = cryptor_raw(i, key, n)
        encoded_bytes = int_to_bytes(encoded_value)
        result.append(len(encoded_bytes))  # Store the length of the encoded segment
        result.extend(encoded_bytes)
    return bytearray(result)
    
class RSA:
    def __init__(self)->None:
        self.p = prime_number_greater_than(random.randint(1_000_000, 1_000_000_000))
        self.q = prime_number_greater_than(random.randint(1_000_000, 1_000_000_000))
        assert self.p != self.q
        self.n = self.p*self.q
        self.phi = (self.p-1)*(self.q-1)
        self.public_key = self.__public_key()
        self.private_key = self.__private_key()
    def __public_key(self):
        # for e in [3, 5, 17, 257, 65537]:
            # if e < self.phi and is_coprime(e, self.phi): return e
        for e in range(2+1, self.phi):
            if is_coprime(e, self.phi): return e
        raise ValueError("Failed to find a valid public key")
    def __private_key(self):
        return modular_inverse(self.public_key, self.phi)
    
    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}(\n"
                f"    p={self.p},\n"
                f"    q={self.q},\n"
                f"    phi={self.phi},\n"
                f"    public_key={self.public_key},\n"
                f"    private_key={self.private_key},\n"
                f"    n={self.n}\n)")
    def decryptor_raw(self, data:int)->int:
        return cryptor_raw(data, self.private_key, self.n)
    def decryptor(self, data:bytearray)->bytearray:
        decrypted = []
        idx = 0
        while idx < len(data):
            segment_length = data[idx]
            idx += 1
            encoded_value = 0
            for j in range(segment_length):
                encoded_value = encoded_value * 255 + data[idx]
                idx += 1
            decrypted_value = self.decryptor_raw(encoded_value)
            decrypted.append(decrypted_value)
        return bytearray(decrypted)


if __name__ == "__main__":
    # client = RSA()
    # client_pubkey = client.public_key
    # client_n = client.n

    server = RSA()
    print(server)
    server_pubkey = server.public_key
    server_n = server.n
    
    m = 999
    print(f"original message : {m}")
    c = cryptor_raw(m, key=server_pubkey, n=server_n)
    print(f"encrypted message : {c}")
    m = server.decryptor_raw(c)
    print(f"decrypted message : {m}")
    

    # client want to send to server
    message = bytearray(b"My name is Laksh Kumar Sisodiya.")
    print(message)
    message_encrypted = cryptor(message, key=server_pubkey, n=server_n)
    print(message_encrypted)
    message_decrypted = server.decryptor(message_encrypted)
    print(message_decrypted)

    # handshake ig signature ...
