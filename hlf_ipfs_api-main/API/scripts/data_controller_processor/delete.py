#!/bin/python3
from pathlib import Path
from threading import Thread
import subprocess
import os


id = input("Id: ")
os.environ['FABRIC_CFG_PATH'] = "../config/"
#HLF
os.chdir(str(Path.home()) + "/HLF/fabric/bin")
cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
channel = "main-channel"
label = "auth"
#repr escapes new lines
function = '{"Args":["Delete","'+ id +'"]}'
orderer = "cronus"
command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
proc = subprocess.Popen(command, stdout=subprocess.PIPE)
lines = proc.stdout.readlines()
print(lines)
