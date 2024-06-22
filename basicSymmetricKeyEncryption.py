import secrets, struct

class BasicSymmetricKeyEncrpter:
    def __init__(self, key) -> None:
        assert len(key)%4 == 0 and len(key)>=12, "key len must be multiple of 4 and greater than or equal to 12"
        self.key = key
        self.key_len = len(key)
        
    @classmethod
    def from_random_key(cls, key_len=32):
        return BasicSymmetricKeyEncrpter(key = secrets.token_bytes(key_len))
    
    def preprocess(self, data):
        length_bits = len(data) * 8 
        data += b'\x80' 
        while len(data) % self.key_len != self.key_len-8:
            data += b'\x00'
        data += length_bits.to_bytes(8, byteorder='big')
        return data
    
    def postprocess(self, data):
        length_bits = int.from_bytes(data[-8:], byteorder='big') 
        assert data[length_bits//8] == 128
        return data[:length_bits//8]

    def encrypt_chunk(self, chunk):
        formater = f'>{self.key_len//4}I'
        chunk = struct.unpack(formater, chunk)
        key = struct.unpack(formater, self.key)
        return struct.pack(formater, *[d ^ k for d, k in zip(chunk, key)])

    def chunk_iter(self, msg):
        for i in range(0, len(msg), self.key_len):
            yield msg[i:i+self.key_len]
    
    def encrypt(self, data):
        data = self.preprocess(data)
        result = b''
        for chunk in self.chunk_iter(data):
            key = self.encrypt_chunk(chunk)
            result += key
        return result
    
    def decrypt(self, data):
        result = b''
        for chunk in self.chunk_iter(data):
            result += self.encrypt_chunk(chunk)
            key = chunk
        return self.postprocess(result)

if __name__ == '__main__':
        
    original_data = b'Hello, My name is Laksh Kumar Sisodiya.'
    
    encrpter = BasicSymmetricKeyEncrpter.from_random_key(key_len=12)
    encrypted_data = encrpter.encrypt(original_data)
    decrypted_data = encrpter.decrypt(encrypted_data)
    
    assert (original_data == decrypted_data)
    
    print(f"LEN[{len(original_data)}] original_data : ", original_data)
    print(f"LEN[{len(encrypted_data)}] encrypted_data : ", encrypted_data)
    print(f"LEN[{len(decrypted_data)}] decrypted_data : ", decrypted_data)
    
    
    