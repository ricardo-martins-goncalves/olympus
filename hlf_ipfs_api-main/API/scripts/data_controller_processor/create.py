#!/bin/python3
from pathlib import Path
from threading import Thread
import subprocess
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes

id = int(input("Id: "))
role = input("Role: ")
os.environ['FABRIC_CFG_PATH'] = "../config/"

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
    return public_key.decode(), private_key.decode()


pk,sk = create_key_pair()
#HLF
os.chdir(str(Path.home()) + "/HLF/fabric/bin")
cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
channel = "main-channel"
label = "auth"
#repr escapes new lines
function = '{"Args":["Create","'+ str(id) +'","' + role + '","' + repr(pk) +'"]}'
orderer = "cronus"
command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
proc = subprocess.Popen(command, stdout=subprocess.PIPE)
lines = proc.stdout.readlines()
print(lines)
#store private key
os.chdir(str(Path.home()) + "/API/scripts/data_controller_processor")
aux = Path(f'admins_private_keys/{role}_{id}.pem')
aux.parent.mkdir(exist_ok=True, parents=True)
f = open(f'admins_private_keys/{role}_{id}.pem', "w")
f.write(sk)
f.close()
