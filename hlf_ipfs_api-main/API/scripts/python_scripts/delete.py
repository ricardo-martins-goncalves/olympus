#!/bin/python3
from pathlib import Path
from threading import Thread
import subprocess
import os
url = "http://zeus.alpha.olympus.pt:8000/delete/"
i = int(input("Start at: "))
end = int(input("End at: "))
os.environ['FABRIC_CFG_PATH'] = "../config/"



def thread_delete(i):
    asset_id = i
    #API
    cookies = "cookies/cookies"+ str(i) +".txt"
    curl = ["curl", "-s", "-c", cookies, "-b", cookies, "-e", url]
    command = curl + [url]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    (lines, err) = proc.communicate()
    proc_status = proc.wait()
    cookies_file = open(cookies, "r")
    lines = cookies_file.readlines()
    lines = lines[4].split("csrftoken")
    django_token= lines[-1].strip()
    tmp = ["-d", "csrfmiddlewaretoken=" + django_token + "&assetid=" + str(asset_id), "-X", "POST", url]
    command = curl + tmp
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    (lines, err) = proc.communicate()
    proc_status = proc.wait()
    cookies_file.close()
    #HLF
    last_path = os.getcwd()
    os.chdir(str(Path.home()) + "/HLF/fabric/bin")
    cafile = "../../organizations/ordererOrganizations/omega.olympus.pt/msp/tlscacerts/ca-omega-olympus-pt-7054.pem"
    channel = "main-channel"
    label = "occv1"
    function = '{"Args":["DeleteAsset","'+ str(asset_id) +'"]}'
    orderer = "cronus"
    command = ["./peer", "chaincode", "invoke", "-o", orderer + ".omega.olympus.pt:7050", "--tls", "--cafile", cafile, "-C", channel, "-n", label, "-c", function]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    os.chdir(last_path)
    os.remove(cookies)

threads = []
while i <= end:
    t = Thread(target=thread_delete, args=(i,))
    threads.append(t)
    t.start()
    i = i+1
# Wait for all of them to finish
for x in threads:
    x.join()
