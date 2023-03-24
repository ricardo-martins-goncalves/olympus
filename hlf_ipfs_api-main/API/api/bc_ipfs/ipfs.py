import json
import hashlib
import subprocess
import os
from pathlib import Path
from threading import Timer
from time import sleep

from .hlf import HLF
from .sym_crypto import CIPHER as aes
from .assym_crypto import RSA as rsa


BUF_SIZE = 65536
key = aes.get_key()

class IPFS:
    def write(form, public_key):
        f = open("temp.txt", "wb")
        tmp = form.cleaned_data
        tmp['public_key'] = public_key
        json_info = json.dumps(tmp, indent=4, sort_keys=True, default=str)
        json_info_cipher=aes.encrypt(json_info,key)
        f.write(json_info_cipher)
        f.close()
        # add file to IPFS
        proc = subprocess.Popen(['ipfs-cluster-ctl', 'add', 'temp.txt'], stdout=subprocess.PIPE)
        lines = proc.stdout.readlines()
        # added QmWuzPSgWNLKRbL7vTpup7qYMJ5cDQM7x3cJGRMdhuNocF temp.txt
        str_split = lines[0].decode().split(" ")
        # hash with sha256
        sha256 = hashlib.sha256()
        with open("temp.txt", 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        hash = "{0}".format(sha256.hexdigest())
        os.remove("temp.txt")
        if str_split[0] == "added" and hash != None:
            return str_split[1], hash
        else:
            return None


    def write_survey(fields):
        f = open("temp.txt", "wb")
        json_info = json.dumps(fields, indent=4, sort_keys=True, default=str)
        json_info_cipher=aes.encrypt(json_info,key)
        f.write(json_info_cipher)
        f.close()
        # add file to IPFS
        proc = subprocess.Popen(['ipfs-cluster-ctl', 'add', 'temp.txt'], stdout=subprocess.PIPE)
        lines = proc.stdout.readlines()
        # added QmWuzPSgWNLKRbL7vTpup7qYMJ5cDQM7x3cJGRMdhuNocF temp.txt
        str_split = lines[0].decode().split(" ")
        # hash with sha256
        sha256 = hashlib.sha256()
        with open("temp.txt", 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        hash = "{0}".format(sha256.hexdigest())
        os.remove("temp.txt")
        if str_split[0] == "added" and hash != None:
            return str_split[1], hash
        else:
            return None





    def read(cid):
        kill = lambda process: process.kill()
        proc = subprocess.Popen(['ipfs', 'get', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timer = Timer(3, kill, [proc])
        try:
            timer.start()
            lines = proc.stdout.readlines()
            if os.path.exists(cid):
                f = open(cid, "rb")
                ipfs_string_cipher = f.read()
                ipfs_string = aes.decrypt(ipfs_string_cipher, key)
                sha256 = hashlib.sha256()
                with open(cid, 'rb') as f:
                    while True:
                        data = f.read(BUF_SIZE)
                        if not data:
                            break
                        sha256.update(data)
                hash = "{0}".format(sha256.hexdigest())
                f.close()
                os.remove(cid)
                ipfs_dict = json.loads(ipfs_string)
                public_key_bytes = ipfs_dict['public_key'].encode()
                return ipfs_string, hash
            else:
                return None, None
        finally:
            timer.cancel()

    def read_survey(cid):
        kill = lambda process: process.kill()
        proc = subprocess.Popen(['ipfs', 'get', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timer = Timer(3, kill, [proc])
        try:
            timer.start()
            lines = proc.stdout.readlines()
            if os.path.exists(cid):
                f = open(cid, "rb")
                ipfs_string_cipher = f.read()
                ipfs_string = aes.decrypt(ipfs_string_cipher, key)
                sha256 = hashlib.sha256()
                f.close()
                os.remove(cid)
                ipfs_dict = json.loads(ipfs_string)
                return ipfs_dict
            else:
                return None
        finally:
            timer.cancel()





    def delete(cid):
        command = "~/gopath/bin/ipfs-cluster-ctl pin rm " + str(cid)
        proc = subprocess.Popen(command, shell=True,  stdout=subprocess.PIPE)
        lines = proc.stdout.readlines()
        pinned = "pin is not part of the pinset" not in lines[2].decode()
        command = "~/gopath/bin/ipfs-cluster-ctl ipfs gc"
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        lines = proc.stdout.readlines()
        removed = "-" not in lines[2].decode()
        if pinned and not removed:
            return True
        else:
            return False

    def verify_signature(cid, signature):
        kill = lambda process: process.kill()
        proc = subprocess.Popen(['ipfs', 'get', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timer = Timer(2, kill, [proc])
        try:
            timer.start()
            lines = proc.stdout.readlines()
            if os.path.exists(cid):
                f = open(cid, "rb")
                ipfs_string_cipher = f.read()
                ipfs_string = aes.decrypt(ipfs_string_cipher, key)
                sha256 = hashlib.sha256()
                with open(cid, 'rb') as f:
                    while True:
                        data = f.read(BUF_SIZE)
                        if not data:
                            break
                        sha256.update(data)
                hash = "{0}".format(sha256.hexdigest())
                f.close()
                os.remove(cid)
                ipfs_dict = json.loads(ipfs_string)
                public_key_bytes = ipfs_dict['public_key'].encode()
                if public_key_bytes is None:
                    return None
                if rsa.verify(public_key_bytes, cid, signature):
                    return True
                else:
                    return False
        finally:
            timer.cancel()

    def get_public_key(cid):
        kill = lambda process: process.kill()
        proc = subprocess.Popen(['ipfs', 'get', cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = proc.stdout.readlines()
        if os.path.exists(cid):
            f = open(cid, "rb")
            ipfs_string_cipher = f.read()
            ipfs_string = aes.decrypt(ipfs_string_cipher, key)
            with open(cid, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
            f.close()
            os.remove(cid)
            ipfs_dict = json.loads(ipfs_string)
            return ipfs_dict['public_key']

    def change_password(cid, new_public_key):
        ipfs_string, ipfs_hash = IPFS.read(cid)
        ipfs_dict = json.loads(ipfs_string)
        ipfs_dict['public_key'] = new_public_key
        result = IPFS.delete(cid)
        if result is True:
            f = open("temp.txt", "wb")
            json_info = json.dumps(ipfs_dict, indent=4, sort_keys=True, default=str)
            json_info_cipher = aes.encrypt(json_info, key)
            f.write(json_info_cipher)
            f.close()
            # add file to IPFS
            proc = subprocess.Popen(['ipfs-cluster-ctl', 'add', 'temp.txt'], stdout=subprocess.PIPE)
            lines = proc.stdout.readlines()
            # added QmWuzPSgWNLKRbL7vTpup7qYMJ5cDQM7x3cJGRMdhuNocF temp.txt
            str_split = lines[0].decode().split(" ")
            # hash with sha256
            sha256 = hashlib.sha256()
            with open("temp.txt", 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha256.update(data)
            hash = "{0}".format(sha256.hexdigest())
            os.remove("temp.txt")
            if str_split[0] == "added" and hash != None:
                return str_split[1], hash
            else:
                return None, None
        else:
            return None, None