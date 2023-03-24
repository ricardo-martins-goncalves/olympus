import base64
import hashlib
import os
from pathlib import Path

from Crypto import Random
from Crypto.Cipher import AES

bs = AES.block_size

class CIPHER:
    def create_key():
        os.chdir(str(Path.home()) + "/API")
        f = open("key.txt", "wb")
        key = os.urandom(32)
        f.write(key)
        f.close()

    def get_key():
        os.chdir(str(Path.home()) + "/API")
        f = open("key.txt", "rb")
        key = f.read()
        f.close()
        return key

    def encrypt(plaintext, key):
        raw = plaintext.encode('utf-8')
        raw = CIPHER.pad(raw)
        iv = Random.new().read(bs)
        ciphertext = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + ciphertext.encrypt(raw))

    def decrypt(ciphertext, key):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:bs]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return CIPHER.unpad(cipher.decrypt(ciphertext[bs:])).decode('utf-8')

    @staticmethod
    def pad(text):
        return text + (bs - len(text) % bs) * chr(bs - len(text) % bs).encode('utf-8')

    @staticmethod
    def unpad(text):
        return text[:-ord(text[len(text) - 1:])]

