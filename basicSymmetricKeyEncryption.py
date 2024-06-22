import secrets, struct
# from sha256 import sha256 as minesha256
from hashlib import sha256 as hashlibsha256
from itertools import cycle

def sha256(x):
    # return minesha256(x)
    return hashlibsha256(x).hexdigest()

def rotate(x, n, t=32):
    """clockwise rotate a t-bit integer to n positions"""
    return (x >> n) | (x << (t - n))
def rotate_anti(x, n, t=32):
    """anti clockwise rotate a t-bit integer to n positions"""
    return (x << n) | (x >> (t - n))

class BasicSymmetricKeyEncrpter:
    def __init__(self, key) -> None:
        assert len(key)%4 == 0 and len(key)>=12, "key len must be multiple of 4 and greater than or equal to 12"
        self.key = key
        self.key_len = len(key)
        
    @classmethod
    def from_random_key(cls, key_len=32):
        return BasicSymmetricKeyEncrpter(key = secrets.token_bytes(key_len))
    
    def encrypt_chunk(self, chunk, key):
        return bytes(a ^ b for a, b in zip(chunk, cycle(key)))
    
    def chunk_iter(self, msg):
        for i in range(0, len(msg), self.key_len):
            yield msg[i:i+self.key_len]

    @staticmethod
    def new_key(old_key, data_last):
        result_key = bytearray(b for b in sha256(old_key + data_last)[2:2+len(old_key)].encode())
        return result_key
    
    def encrypt(self, data):
        data = data
        result = b''
        key = self.key
        for chunk in self.chunk_iter(data):
            result += self.encrypt_chunk(chunk, key)
            key = self.new_key(key, chunk)
        return result
    
    def decrypt(self, data):
        result = b''
        key = self.key
        for chunk in self.chunk_iter(data):
            decrypted = self.encrypt_chunk(chunk, key)
            result += decrypted
            key = self.new_key(key, decrypted)
        return result

if __name__ == '__main__':
    
    original_data = b'Hello, My...'*12
    
    encrpter = BasicSymmetricKeyEncrpter.from_random_key(key_len=12)
    encrypted_data = encrpter.encrypt(original_data)
    decrypted_data = encrpter.decrypt(encrypted_data)
    
    assert (original_data == decrypted_data)
    
    with open('basicSymmetricKeyEncryption.crypt', 'wb') as f:
        f.write(encrypted_data)
    
    print(f"LEN[{len(original_data)}] original_data : ", original_data)
    print(f"LEN[{len(encrypted_data)}] encrypted_data : ", encrypted_data)
    print(f"LEN[{len(decrypted_data)}] decrypted_data : ", decrypted_data)
    
    
    
