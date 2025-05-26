from pydantic import BaseModel, field_validator, computed_field, model_validator
from typing import Literal


class Base2NConfig(BaseModel):
    chars: bytes
    
    sentinel: bytes
    padding_char: bytes
    
    @classmethod
    def from_base64(cls):
        return cls(
            chars=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            sentinel=b'\x00',
            padding_char=b'='
        )
    @classmethod
    def from_base64_urlsafe(cls):
        return cls(
            chars=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            sentinel=b'\x00',
            padding_char=b'='
        )
    
    @classmethod
    def from_base32(cls):
        # NOTE: NOT SAME AS STANDARD BASE32, PADDING MAY HAVE SOME BUGS, BUT IT IS REVERSABLE SO WE CAN USE THIS
        return cls(
            chars=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            sentinel=b'\x00',
            padding_char=b'='
        )
    @classmethod
    def from_base32_hex(cls):
        # NOTE: NOT SAME AS STANDARD BASE32, PADDING MAY HAVE SOME BUGS, BUT IT IS REVERSABLE SO WE CAN USE THIS
        return cls(
            chars=b"0123456789ABCDEFGHIJKLMNOPQRSTUV",
            sentinel=b'\x00',
            padding_char=b'='
        )
    
    @field_validator('chars')
    @classmethod
    def ensure_unique_sorted_chars(cls, chars: bytes) -> bytes:
        assert len(chars) == len(set(chars)), "chars must be a unique byte sequence"
        assert (
            len(chars) == 2 or 
            len(chars) == 4 or 
            len(chars) == 8 or 
            len(chars) == 16 or
            len(chars) == 32 or
            len(chars) == 64 or
            len(chars) == 128
        ), "chars must be a unique sorted byte sequence of length 2, 4, 8, 16, 32, 64, or 128"
        return chars
    @field_validator('sentinel')
    @classmethod
    def ensure_byte_sentinel(cls, sentinel: bytes) -> bytes:
        assert len(sentinel) == 1, "sentinel must be a single byte"
        return sentinel
    @field_validator('padding_char')
    @classmethod
    def ensure_byte_padding_char(cls, padding_char: bytes) -> bytes:
        assert len(padding_char) == 1, "padding_char must be a single byte"
        return padding_char
    @computed_field
    @property
    def n(self) -> Literal[1, 2, 3, 4, 5, 6, 7]:
        if self.base == 2: return 1
        if self.base == 4: return 2
        if self.base == 8: return 3
        if self.base == 16: return 4
        if self.base == 32: return 5
        if self.base == 64: return 6
        if self.base == 128: return 7
        raise ValueError(f"Unsupported base: {self.base}")
    @computed_field
    @property
    def base(self) -> Literal[2, 4, 8, 16, 32, 64, 128]:
        return len(self.chars) # type: ignore
    @model_validator(mode='after')
    def ensure_padding_char_not_in_chars(self):
        assert self.padding_char not in self.chars, "padding_char must not be in chars"
        return self
    @computed_field
    @property
    def padding_length(self) -> Literal[1, 3, 5, 7]:
        if self.base == 2: return 1
        if self.base == 4: return 1
        if self.base == 8: return 3
        if self.base == 16: return 1
        if self.base == 32: return 5
        if self.base == 64: return 3
        if self.base == 128: return 7
        raise ValueError(f"Unsupported base: {self.base}")
    @computed_field
    @property
    def is_printable(self) -> bool:
        return all(32 <= c < 127 for c in self.chars) and self.padding_char[0] >= 32 and self.padding_char[0] < 127
    

class BitPacking:
    ##############################################################
    #                     size 2 => 1 bites                     #   
    ##############################################################
    # 256 => 8 and 8*[1] % 1 == 0
    @staticmethod
    def encode_2(data: bytes) -> bytes:
        result_size = (len(data) // 1) * 8
        result = bytearray(result_size)
        for idx in range(len(data) // 1):
            result[idx * 8] = data[idx * 1] >> 7
            result[idx * 8 + 1] = (data[idx * 1] & 0b01000000) >> 6
            result[idx * 8 + 2] = (data[idx * 1] & 0b00100000) >> 5
            result[idx * 8 + 3] = (data[idx * 1] & 0b00010000) >> 4
            result[idx * 8 + 4] = (data[idx * 1] & 0b00001000) >> 3
            result[idx * 8 + 5] = (data[idx * 1] & 0b00000100) >> 2
            result[idx * 8 + 6] = (data[idx * 1] & 0b00000010) >> 1
            result[idx * 8 + 7] = data[idx * 1] & 0b00000001
        return bytes(result)
    @staticmethod
    def decode_2(data: bytes) -> bytes:
        result_size = (len(data) // 8) * 1
        result = bytearray(result_size)
        for idx in range(len(data) // 8):
            result[idx * 1] = ((data[idx * 8] << 7) | 
                               (data[idx * 8 + 1] << 6) | 
                               (data[idx * 8 + 2] << 5) |
                               (data[idx * 8 + 3] << 4) |
                               (data[idx * 8 + 4] << 3) |
                               (data[idx * 8 + 5] << 2) |
                               (data[idx * 8 + 6] << 1) |
                               data[idx * 8 + 7]) 
        return bytes(result)

    ##############################################################
    #                     size 4 => 2 bites                     #   
    ##############################################################
    # 256 => 8 and 8*[1] % 2 == 0
    @staticmethod
    def encode_4(data: bytes) -> bytes:
        result_size = (len(data) // 1) * 4
        result = bytearray(result_size)
        for idx in range(len(data) // 1):
            result[idx * 4] = data[idx * 1] >> 6
            result[idx * 4 + 1] = (data[idx * 1] & 0b00110000) >> 4
            result[idx * 4 + 2] = (data[idx * 1] & 0b00001100) >> 2
            result[idx * 4 + 3] = data[idx * 1] & 0b00000011
        return bytes(result)
    @staticmethod
    def decode_4(data: bytes) -> bytes:
        result_size = (len(data) // 4) * 1
        result = bytearray(result_size)
        for idx in range(len(data) // 4):
            result[idx * 1] = ((data[idx * 4] << 6) | 
                               (data[idx * 4 + 1] << 4) | 
                               (data[idx * 4 + 2] << 2) |
                               data[idx * 4 + 3]) 
        return bytes(result)

    ##############################################################
    #                     size 8 => 3 bites                      #   
    ##############################################################
    # 256 => 8 and 8*[3] % 3 == 0
    @staticmethod
    def encode_8(data: bytes) -> bytes:
        result_size = (len(data) // 3) * 8
        result = bytearray(result_size)
        for idx in range(len(data) // 3):
            result[idx * 8] = data[idx * 3] >> 5
            result[idx * 8 + 1] = (data[idx * 3] & 0b00011111) >> 2
            result[idx * 8 + 2] = (data[idx * 3] & 0b00000011) << 1 | (data[idx * 3 + 1] >> 7)
            result[idx * 8 + 3] = (data[idx * 3 + 1] & 0b01111111) >> 4
            result[idx * 8 + 4] = (data[idx * 3 + 1] & 0b00001111) >> 1
            result[idx * 8 + 5] = (data[idx * 3 + 1] & 0b00000001) << 2 | (data[idx * 3 + 2] >> 6)
            result[idx * 8 + 6] = (data[idx * 3 + 2] & 0b00111111) >> 3
            result[idx * 8 + 7] = data[idx * 3 + 2] & 0b00000111
        return bytes(result)
    @staticmethod
    def decode_8(data: bytes) -> bytes:
        result_size = (len(data) // 8) * 3
        result = bytearray(result_size)
        for idx in range(len(data) // 8):
            result[idx * 3] = (data[idx * 8] << 5) | (data[idx * 8 + 1] << 2) | (data[idx * 8 + 2] >> 1)
            result[idx * 3 + 1] = ((data[idx * 8 + 2] & 0b00000001) << 7) | (data[idx * 8 + 3] << 4) | (data[idx * 8 + 4] << 1) | (data[idx * 8 + 5] >> 2)
            result[idx * 3 + 2] = ((data[idx * 8 + 5] & 0b00000011) << 6) | (data[idx * 8 + 6] << 3) | data[idx * 8 + 7]
        return bytes(result)
    
    ##############################################################
    #                     size 16 => 4 bites                     #   
    ##############################################################
    # 256 => 8 and 8*[1] % 4 == 0
    @staticmethod
    def encode_16(data: bytes) -> bytes:
        result_size = (len(data) // 1) * 2
        result = bytearray(result_size)
        for idx in range(len(data) // 1):
            result[idx * 2] = data[idx * 1] >> 4
            result[idx * 2 + 1] = data[idx * 1] & 0b00001111
        return bytes(result)
    @staticmethod
    def decode_16(data: bytes) -> bytes:
        result_size = (len(data) // 2) * 1
        result = bytearray(result_size)
        for idx in range(len(data) // 2):
            result[idx * 1] = (data[idx * 2] << 4) | data[idx * 2 + 1]
        return bytes(result)
    
    ##############################################################
    #                     size 32 => 5 bites                     #   
    ##############################################################
    # 256 => 8 and 8*[5] % 5 == 0
    @staticmethod
    def encode_32(data: bytes) -> bytes:
        result_size = (len(data) // 5) * 8
        result = bytearray(result_size)
        for idx in range(len(data) // 5):
            result[idx * 8] = data[idx * 5] >> 3
            result[idx * 8 + 1] = (data[idx * 5] & 0b00000111) << 2 | (data[idx * 5 + 1] >> 6)
            result[idx * 8 + 2] = (data[idx * 5 + 1] & 0b00111111) >> 1
            result[idx * 8 + 3] = (data[idx * 5 + 1] & 0b00000001) << 4 | (data[idx * 5 + 2] >> 4)
            result[idx * 8 + 4] = (data[idx * 5 + 2] & 0b00001111) << 1 | (data[idx * 5 + 3] >> 7)
            result[idx * 8 + 5] = (data[idx * 5 + 3] & 0b01111111) >> 2
            result[idx * 8 + 6] = (data[idx * 5 + 3] & 0b00000011) << 3 | (data[idx * 5 + 4] >> 5)
            result[idx * 8 + 7] = data[idx * 5 + 4] & 0b00011111
        return bytes(result)
    @staticmethod
    def decode_32(data: bytes) -> bytes:
        result_size = (len(data) // 8) * 5
        result = bytearray(result_size)
        for idx in range(len(data) // 8):
            result[idx * 5] = (data[idx * 8] << 3) | (data[idx * 8 + 1] >> 2)
            result[idx * 5 + 1] = ((data[idx * 8 + 1] & 0b00000011) << 6) | (data[idx * 8 + 2] << 1) | (data[idx * 8 + 3] >> 4)
            result[idx * 5 + 2] = ((data[idx * 8 + 3] & 0b00001111) << 4) | (data[idx * 8 + 4] >> 1)
            result[idx * 5 + 3] = ((data[idx * 8 + 4] & 0b00000001) << 7) | (data[idx * 8 + 5] << 2) | (data[idx * 8 + 6] >> 3)
            result[idx * 5 + 4] = ((data[idx * 8 + 6] & 0b00000111) << 5) | data[idx * 8 + 7]
        return bytes(result)
    
    ##############################################################
    #                     size 64 => 6 bites                     #   
    ##############################################################
    # 256 => 8 and 8*[3] % 6 == 0
    @staticmethod
    def encode_64(data: bytes) -> bytes:
        result_size = (len(data) // 3) * 4
        result = bytearray(result_size)
        for idx in range(len(data) // 3):
            result[idx * 4] = data[idx * 3] >> 2
            result[idx * 4 + 1] = (data[idx * 3] & 0b00000011) << 4 | (data[idx * 3 + 1] >> 4)
            result[idx * 4 + 2] = (data[idx * 3 + 1] & 0b00001111) << 2 | (data[idx * 3 + 2] >> 6)
            result[idx * 4 + 3] = data[idx * 3 + 2] & 0b00111111
        return bytes(result) 
    @staticmethod
    def decode_64(data: bytes) -> bytes:
        result_size = (len(data) // 4) * 3
        result = bytearray(result_size)
        for idx in range(len(data) // 4):
            result[idx * 3] = (data[idx * 4] << 2) | (data[idx * 4 + 1] >> 4)
            result[idx * 3 + 1] = ((data[idx * 4 + 1] & 0b00001111) << 4) | (data[idx * 4 + 2] >> 2)
            result[idx * 3 + 2] = ((data[idx * 4 + 2] & 0b00000011) << 6) | data[idx * 4 + 3]
        return bytes(result)
    
    ##############################################################
    #                     size 128 => 7 bites                     #   
    ##############################################################
    # 256 => 8 and 8*[7] % 7 == 0
    @staticmethod
    def encode_128(data: bytes) -> bytes:
        result_size = (len(data) // 7) * 8
        result = bytearray(result_size)
        for idx in range(len(data) // 7):
            result[idx * 8] = data[idx * 7] >> 1
            result[idx * 8 + 1] = (data[idx * 7] & 0b00000001) << 6 | (data[idx * 7 + 1] >> 2)
            result[idx * 8 + 2] = (data[idx * 7 + 1] & 0b00000011) << 5 | (data[idx * 7 + 2] >> 3)
            result[idx * 8 + 3] = (data[idx * 7 + 2] & 0b00000111) << 4 | (data[idx * 7 + 3] >> 4)
            result[idx * 8 + 4] = (data[idx * 7 + 3] & 0b00001111) << 3 | (data[idx * 7 + 4] >> 5)
            result[idx * 8 + 5] = (data[idx * 7 + 4] & 0b00011111) << 2 | (data[idx * 7 + 5] >> 6)
            result[idx * 8 + 6] = (data[idx * 7 + 5] & 0b00111111) << 1 | (data[idx * 7 + 6] >> 7)
            result[idx * 8 + 7] = data[idx * 7 + 6] & 0b01111111
        return bytes(result) 
    @staticmethod
    def decode_128(data: bytes) -> bytes:
        result_size = (len(data) // 8) * 7
        result = bytearray(result_size)
        for idx in range(len(data) // 8):
            result[idx * 7] = (data[idx * 8] << 1) | (data[idx * 8 + 1] >> 6)
            result[idx * 7 + 1] = ((data[idx * 8 + 1] & 0b00111111) << 2) | (data[idx * 8 + 2] >> 5)
            result[idx * 7 + 2] = ((data[idx * 8 + 2] & 0b00011111) << 3) | (data[idx * 8 + 3] >> 4)
            result[idx * 7 + 3] = ((data[idx * 8 + 3] & 0b00001111) << 4) | (data[idx * 8 + 4] >> 3)
            result[idx * 7 + 4] = ((data[idx * 8 + 4] & 0b00000111) << 5) | (data[idx * 8 + 5] >> 2)
            result[idx * 7 + 5] = ((data[idx * 8 + 5] & 0b00000011) << 6) | (data[idx * 8 + 6] >> 1)
            result[idx * 7 + 6] = ((data[idx * 8 + 6] & 0b00000001) << 7) | data[idx * 8 + 7]
        return bytes(result)
    
class Base2N(BitPacking):
    def __init__(self, config: Base2NConfig):
        self.base = config.base
        self.n = config.n
        self.sentinel = config.sentinel
        self.padding_char = config.padding_char
        self.padding_length = config.padding_length
        self.is_printable = config.is_printable
        
        self.chars = config.chars # len == 2, 4, 8, 16, 32, 64, or 128
        self.reverse_chars = bytearray(256)
        for i, c in enumerate(self.chars): self.reverse_chars[c] = i
        # self.reverse_chars[self.padding_char_ord] = 0 # not needed as bytearray already initialized with 0
        
    @property
    def padding_char_ord(self) -> int:
        return self.padding_char[0]
    
    def encode(self, data: bytes) -> bytes:
        padding_length = (self.padding_length - (len(data) % self.padding_length)) % self.padding_length
        if padding_length > 0:
            data += self.sentinel * padding_length
        assert len(data) % self.padding_length == 0, f"Data length must be a multiple of 1 for encoding but got {len(data)}"
        if self.n == 1: result = self.encode_2(data)
        elif self.n == 2: result = self.encode_4(data)
        elif self.n == 3: result = self.encode_8(data)
        elif self.n == 4: result = self.encode_16(data)
        elif self.n == 5: result = self.encode_32(data)
        elif self.n == 6: result = self.encode_64(data)
        elif self.n == 7: result = self.encode_128(data)
        else: raise ValueError(f"Unsupported base: {self.n}")
        assert all(i < self.base for i in result), f"Encoded data must be less than {self.base} for Base{self.base} encoding"
        if padding_length > 0: 
            result = bytes(self.chars[i] for i in result[:-padding_length])
            result += self.padding_char * padding_length
        else:
            result = bytes(self.chars[i] for i in result)
        return result
    def decode(self, data: bytes) -> bytes:
        padding_length = 0
        for c in reversed(data):
            if c == self.padding_char_ord: padding_length += 1
            else: break
            
        data = bytes(self.reverse_chars[i] for i in data)
        
        __mod_len = {1: 8, 2: 4, 3: 8, 4: 2, 5: 8, 6: 4, 7: 8}[self.n]
        assert len(data) % __mod_len == 0, f"Data length must be a multiple of {__mod_len} for decoding but got {len(data)}"
        if self.n == 1: result = self.decode_2(data)
        elif self.n == 2: result = self.decode_4(data)
        elif self.n == 3: result = self.decode_8(data)
        elif self.n == 4: result = self.decode_16(data)
        elif self.n == 5: result = self.decode_32(data)
        elif self.n == 6: result = self.decode_64(data)
        elif self.n == 7: result = self.decode_128(data)
        else: raise ValueError(f"Unsupported base: {self.n}")
        return result[:-padding_length] if padding_length > 0 else result
    
    def encode2(self, data: str) -> str:
        assert self.is_printable, "please use encode() instead of encode2()"
        return self.encode(
            data.encode(encoding='utf-8', errors='strict')
        ).decode(encoding='utf-8', errors='strict')
    def decode2(self, data: str) -> str:
        assert self.is_printable, "please use decode() instead of decode2()"
        return self.decode(
            data.encode(encoding='utf-8', errors='strict')
        ).decode(encoding='utf-8', errors='strict')


from base64 import b64decode, b64encode
if __name__ == "__main__":
    baseNConfig = Base2NConfig.from_base64()
    base2N = Base2N(baseNConfig)
    
    data = b'\xfb\xff\xbf\xffhello world'
    endata = base2N.encode(data)
    print(endata)
    dedata = base2N.decode(endata)
    assert dedata == data, f"Base2N decode mismatch {data}"
    print(dedata)
    
    endata = b64encode(data)
    assert endata == base2N.encode(data), f"Base2N encode mismatch with Base64 {data}"
    print(endata)
    
    dedata = b64decode(endata)
    print(dedata)
    