import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes


class RSA:
    def create_key_pair():
        key_pair = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048)
        private_key = key_pair.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        public_key = key_pair.public_key().public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo)
        return public_key, private_key

    def sign(private_key_bytes, message):
        private_key = crypto_serialization.load_pem_private_key(private_key_bytes, password=None, backend=crypto_default_backend())
        return private_key.sign(message.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


    def verify(public_key_bytes, message, signature):
        public_key = crypto_serialization.load_pem_public_key(public_key_bytes, backend=crypto_default_backend())
        try:
            public_key.verify(signature, message.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except InvalidSignature:
            return False


pk, sk = RSA.create_key_pair()
msg = "Hello World"

with open("sk.pem","wb")as f:
    f.write(sk)
with open("sk.pem", "rb")as f:
    sk_file = f.read()
with open("pk.pem","wb")as f:
    f.write(pk)
with open("pk.pem", "rb")as f:
    pk_file = f.read()

signature = RSA.sign(sk_file, msg)
msg = "Hello World"
valid_sign = RSA.verify(pk_file, msg, signature)
print(valid_sign)
