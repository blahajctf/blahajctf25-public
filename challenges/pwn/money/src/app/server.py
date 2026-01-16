#!/usr/bin/python3 -u

from base64 import b64decode
import os
from uuid import uuid4

try:
    inp = input("base64 encoded script > ")
except EOFError:
    exit(0)

recv = b64decode(inp)

filename = str(uuid4())
with open(f"/tmp/{filename}", "wb") as file:
    file.write(recv)

os.system(f"/usr/bin/python3.11 /app/run.py {filename}")
os.system(f"/usr/bin/rm /tmp/{filename}")
