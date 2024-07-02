import secrets, struct
from hashlib import sha256
from itertools import cycle

class BasicSymmetricKeyEncrpter:
    def __init__(self, key) -> None:
        # self.key = key
        self.key = bytearray(key)
        self.key_len = len(key)
        
    @classmethod
    def from_random_key(cls, key_len=32):
        return cls(key = secrets.token_bytes(key_len))
    
    def encrypt_chunk(self, chunk, key):
        # return bytes(a ^ b for a, b in zip(chunk, cycle(key)))
        return bytes(a ^ b for a, b in zip(chunk, key))
    
    @staticmethod
    def new_key(old_key, data_last):
        combined = old_key + data_last
        return bytearray(sha256(combined).digest())
    
    def encrypt(self, data):
        data_len = len(data)
        result = bytearray()
        key = self.key
        
        i = 0
        while data_len > 0:
            chunk = data[i:i+len(key)]
            i+=len(key)
            result.extend(self.encrypt_chunk(chunk, key))
            data_len -= len(key)
            key = self.new_key(key, chunk)
        return result
    
    def decrypt(self, data):
        result = bytearray()
        key = self.key
        data_len = len(data)
        i = 0
        while data_len > 0:
            chunk = data[i:i+len(key)]
            i+=len(key)
            decrypted = self.encrypt_chunk(chunk, key)
            result.extend(decrypted)
            data_len -= len(key)
            key = self.new_key(key, decrypted)
        return result

if __name__ == '__main__':
    
    original_data = b'Hello, My...'*100
    
    encrpter = BasicSymmetricKeyEncrpter.from_random_key(key_len=256)
    encrypted_data = encrpter.encrypt(original_data)
    decrypted_data = encrpter.decrypt(encrypted_data)
    
    assert (original_data == decrypted_data)
    
    # with open('basicSymmetricKeyEncryption.crypt', 'wb') as f:
        # f.write(encrypted_data)
    
    print(f"LEN[{len(original_data)}] original_data : ", original_data)
    print(f"LEN[{len(encrypted_data)}] encrypted_data : ", encrypted_data)
    print(f"LEN[{len(decrypted_data)}] decrypted_data : ", decrypted_data)
    
    
    
