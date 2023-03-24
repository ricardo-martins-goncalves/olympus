import json
import os
import subprocess
from .assym_crypto import RSA
from pathlib import Path


class Auth_HLF:
    def create(id, role, public_key):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "auth"
        function = '{"Args":["Create","' + str(id) + '","' + str(role) + '","' + repr(public_key) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile",
                       cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def read(id):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "auth"
        function = '{"Args":["Read","'+ str(id) +'"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def getRole(id):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "auth"
        function = '{"Args":["GetRole","' + str(id) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def update_public_key(id, public_key):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "auth"
        function = '{"Args":["NewPublicKey","'+ str(id) + '","' + repr(public_key) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def verify_signature(id, signature):
        asset = Auth_HLF.read(id)
        if "status:200" in str(asset):
            asset = asset.decode()
            #remove \\ but not \\n and ' from the private key
            asset = (asset.split('"{'))[1].split('}"')[0].replace("\\n", "***n").replace("\\", "").replace("***n", "\\n").replace("'","")
            asset = "{" + asset + "}"
            asset_dict = json.loads(asset)
            public_key_bytes = asset_dict['publickey'].encode()
            if public_key_bytes is None:
                return None
            if RSA.verify(public_key_bytes, str(id), signature):
                return True
            else:
                return False

        

