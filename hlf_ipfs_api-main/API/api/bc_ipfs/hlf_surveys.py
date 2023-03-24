import json
import os
import subprocess
from .assym_crypto import RSA
from pathlib import Path


class Surveys_HLF:
    def create(id, description, fields,  deadline):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "survey2"
        function = '{"Args":["CreateSurvey","' + str(id) + '","' + str(description) + '","' + str(fields) + '","' + str(deadline) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile",
                       cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def delete(id):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "survey2"
        function = '{"Args":["DeleteSurvey","' + str(id) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
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
        label = "survey2"
        function = '{"Args":["ReadSurvey","' + str(id) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log


    def get_all_surveys():
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "survey2"
        function = '{"Args":["GetAllSurveys"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            assets = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in assets.decode():
                break

        return assets



    def add_cid(id, cid):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "survey2"
        function = '{"Args":["AddCID","' + str(id) + '","' + str(cid) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile",
                       cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def remove_cid(id, cid):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "survey2"
        function = '{"Args":["RemoveCID","' + str(id) + '","' + str(cid) + '"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile",
                       cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log








