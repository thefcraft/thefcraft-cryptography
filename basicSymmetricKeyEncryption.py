import secrets, struct
# from sha256 import sha256 as minesha256
from hashlib import sha256 as hashlibsha256
from itertools import cycle

def sha256(x):
    # return minesha256(x)
    return hashlibsha256(x).hexdigest()


class BasicSymmetricKeyEncrpter:
    def __init__(self, key) -> None:
        self.key = key
        self.key_len = len(key)
        
    @classmethod
    def from_random_key(cls, key_len=32):
        return BasicSymmetricKeyEncrpter(key = secrets.token_bytes(key_len))
    
    def encrypt_chunk(self, chunk, key):
        return bytes(a ^ b for a, b in zip(chunk, cycle(key)))
    
    @staticmethod
    def new_key(old_key, data_last):
        # print(bytes.fromhex(sha256(old_key + data_last)[2:]))
        # result_key = bytearray(b for b in sha256(old_key + data_last)[2:].encode())
        result_key = bytes.fromhex(sha256(old_key + data_last)[2:])
        return result_key
    
    def encrypt(self, data):
        data = data
        result = b''
        key = self.key
        data_len = len(data)
        i = 0
        while data_len > 0:
            chunk = data[i:i+len(key)]
            i+=len(key)
            result += self.encrypt_chunk(chunk, key)
            data_len -= len(key)
            key = self.new_key(key, chunk)
        return result
    
    def decrypt(self, data):
        result = b''
        key = self.key
        data_len = len(data)
        i = 0
        while data_len > 0:
            chunk = data[i:i+len(key)]
            i+=len(key)
            decrypted = self.encrypt_chunk(chunk, key)
            result += decrypted
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
    
    
    
