#!/bin/python3
from threading import Thread
import subprocess
import os
url = "http://zeus.alpha.olympus.pt:8000/create/"
i = input("Start at: ")
file = open("entries.txt", 'r')
lines = file.readlines()


def thread_create(line, i):
    asset_id = i
    client_id = i
    cookies = "cookies/cookies"+ str(i) +".txt"
    curl = ["curl", "-s", "-c", cookies, "-b", cookies, "-e", url]
    fields = line.replace('\t', "").replace('\n', "").split(";")
    name = fields[0]
    email = fields[1]
    phone = fields[2]
    birthday = fields[3]
    address = fields[4]
    consent = "on"
    command = curl + [url]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    lines = proc.stdout.readlines()

    cookies_file = open(cookies, "r")
    lines = cookies_file.readlines()
    lines = lines[4].split("csrftoken")
    django_token= lines[-1].strip()
    data_str = "csrfmiddlewaretoken=" + django_token + "&assetid=" + str(asset_id) + "&clientid=" + str(client_id) + "&name=" + name +"&email=" + email + "&phone=" + phone + "&birthday=" + birthday + "&address=" + address + "&consent=" + consent
    tmp = ["-d", data_str, "-X", "POST", url]
    command = curl + tmp
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    lines = proc.stdout.readlines()
    cookies_file.close()
    os.remove(cookies)

threads = []
for i, line in enumerate(lines):
    t = Thread(target=thread_create, args=(line, i+1))
    threads.append(t)
    t.start()
# Wait for all of them to finish
for x in threads:
    x.join()

file.close()
