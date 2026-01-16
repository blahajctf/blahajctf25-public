import os
from flask import Flask, request
from waitress import serve
app = Flask(__name__)

@app.route('/')
def hello():
    return "hello chat flag is in /getflag. but firewall blocks you!"

@app.route('/getflag')
def getflag():
    if request.cookies.get("user", "") == "admin":
        return "yay you win. your flag is blahaj{w0w_f1rew4ll_bypass}"
    return "no flag for you. you are not the admin."

@app.route('/healthz', methods=['GET'])
def healthcheck():
    return "OK"

if __name__ == '__main__':
    app.run(host = "127.0.0.1", port = 5000)