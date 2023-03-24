import os
import subprocess
from pathlib import Path
from io import StringIO



class HLF:
    def write(asset_id, consents, cid, hash):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["CreateAsset","'+ str(asset_id) +'","'+str(consents)+'","'+cid+'","'+hash+'"]}'

        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def read(asset_id):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["ReadAsset","'+ str(asset_id) +'"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break

        return log

    def update(asset_id, consents, cid, hash):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["UpdateAsset","'+ str(asset_id) +'","'+str(consents)+'","'+cid+'","'+hash+'"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log


    def deleteIPFS(asset_id):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["SetDeleted","'+ str(asset_id) +'"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break

        return log




    def get_all_assets():
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["GetAllAssets"]}'
        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls",
                       "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            assets = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in assets.decode():
                break
        return assets

    def add_cid_to_survey(asset_id, survey_id, cid):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["AddCID","'+ str(asset_id) +'","'+str(survey_id)+'","'+cid+'"]}'

        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log

    def delete_cid_from_survey(asset_id, survey_id, cid):
        os.chdir(str(Path.home()) + "/HLF/fabric/bin")
        os.environ['FABRIC_CFG_PATH'] = "../config/"
        cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
        channel = "main-channel"
        label = "occv3"
        function = '{"Args":["RemoveCID","'+ str(asset_id) +'","'+str(survey_id)+'","'+cid+'"]}'

        orderers = ["atlas", "cronus", "rhea"]
        for orderer in orderers:
            command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
            proc = subprocess.Popen(command, stderr=subprocess.PIPE)
            log = proc.stderr.read()
            if "error getting broadcast client: orderer client failed to connect to" not in log.decode():
                break
        return log
