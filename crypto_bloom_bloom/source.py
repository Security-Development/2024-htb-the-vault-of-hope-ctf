from random import randint, shuffle
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import os

#assert sha256(KEY).hexdigest().startswith('786f36dd7c9d902f1921629161d9b057')

class BBS:
    def __init__(self, bits, length):
        self.bits = bits
        self.out_length = length

    def reset_params(self):
        self.state = randint(2, 2 ** self.bits - 2)
        self.m = getPrime(self.bits//2) * getPrime(self.bits//2) * randint(1, 2)
        print("self.m:", self.m)
    
    def extract_bit(self):
        self.state = pow(self.state, 2, self.m)
        return str(self.state % 2)

    def gen_output(self):
        self.reset_params()
        out = ''
        for _ in range(self.out_length):
            out += self.extract_bit()
        return out

    def encrypt(self, msg):
        out = self.gen_output()
        key = sha256(out.encode()).digest()
        print("key:", key.hex())
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return (iv.hex(), cipher.encrypt(pad(msg.encode(), 16)).hex())

encryptor = BBS(512, 256)
KEY = b"a"*16
FLAG = b"FAKE_FLAG"
enc_messages = []
for msg in "1234567890":
    enc_messages.append([encryptor.encrypt(msg) for _ in range(10)])

enc_flag = AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16))

print(f'{enc_messages}\n')
print(f'{enc_flag.hex()}\n')