import os
import pwd
import multiprocessing
from pickle import MARK, UNICODE, DICT, STOP, load 
from io import BytesIO
from flask import Flask, request, render_template

app = Flask(__name__)
app.config['SECRET_KEY'] = 'blahaj{mrow_why_do_you_keep_making_us_flag_sad_face_3:}'

SANDBOX_USER = 'nonroot'

def unsafe_loader(pickle_data, return_queue):
    try:
        pwnam = pwd.getpwnam(SANDBOX_USER)
        target_uid = pwnam.pw_uid
        target_gid = pwnam.pw_gid
        os.setgid(target_gid)
        os.setuid(target_uid)
        data = load(BytesIO(pickle_data))
        return_queue.put(data)
    except Exception as e:
        return_queue.put({'username': 'error', 'password': 'error'})

def build_creds(username, msg):
    creds = MARK
    creds += UNICODE + b'username\n' + UNICODE + username.encode() + b'\n'
    creds += UNICODE + b'message\n' + UNICODE + msg.encode() + b'\n'
    creds += DICT
    creds += STOP

    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=unsafe_loader, args=(creds, q))
    p.start()
    p.join(timeout=2)

    if p.is_alive():
        p.terminate()
        return {'username': 'timeout', 'password': 'timeout'}

    if not q.empty():
        return q.get()
    return {'username': 'crashed', 'password': 'crashed'}

@app.route('/message', methods=['GET', 'POST'])
def message():
    if request.method == 'POST':
        username = request.form['username']
        msg = request.form['message']
        print(f'[*] {username} sent a message {msg}')
        build_creds(username, msg)
        return render_template('toll.html')
    return render_template('message.html')

@app.route('/healthz', methods=['GET'])
def healthcheck():
    return "OK"

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("ERROR: Docker container must start as root for sandboxing to work.")
        print("Remove 'USER 1001' from your Dockerfile.")
        exit(1)
        
    app.run()