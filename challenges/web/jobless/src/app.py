import os
import hashlib
import uuid
import sqlite3
import subprocess
import tempfile
import shutil
import secrets
import threading
import time
from pathlib import Path
from flask import Flask, request, render_template, make_response, abort, session, send_from_directory

UPLOAD_FOLDER = '/tmp/uploads'
FLAG = "blahaj{i_g0t_Th3_j0B_1350}"
POW_DIFFICULTY = 5
POW_CLEAR_INTERVAL_SECONDS = 10
CHROMIUM_TIMEOUT = 60

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.urandom(24)

USED_POW_HASHES = set()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def clear_pow_set_periodically():
    global USED_POW_HASHES
    while True:
        time.sleep(POW_CLEAR_INTERVAL_SECONDS)
        USED_POW_HASHES.clear()

def visit_and_cleanup_html(uri, html_path):
    temp_dir = None
    try:
        print(f"[*] Bot starting to visit {uri}")
        chromium_path = shutil.which('chromium-browser') or shutil.which('chromium')
        if not chromium_path:
            print("[!] ERROR: chromium-browser or chromium not found in PATH.")
            return
        temp_dir = tempfile.mkdtemp()
        cmd = [chromium_path, '--disable-gpu', '--headless', '--no-sandbox', "--disable-popup-blocking", f'--user-data-dir={temp_dir}', uri]
        subprocess.run(cmd, timeout=CHROMIUM_TIMEOUT, check=True, capture_output=True)
    except Exception as e:
        pass
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        if os.path.exists(html_path):
            os.remove(html_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        pow_solution = request.form.get('pow_solution')
        if not pow_solution: return "Missing PoW solution.", 400
        solution_hash = hashlib.sha256(pow_solution.encode()).hexdigest()
        if solution_hash in USED_POW_HASHES: return "Proof-of-Work solution has already been used (replay attack detected).", 400
        if not solution_hash.startswith('0' * POW_DIFFICULTY): return "Invalid Proof-of-Work. Solution does not produce the required hash prefix.", 400
        USED_POW_HASHES.add(solution_hash)
        
        if 'file' not in request.files or not request.files['file'].filename.endswith('.html'):
            return "Invalid file type. Please upload an HTML file.", 400
        
        file = request.files['file']
        filename = f"{uuid.uuid4()}.html"
        html_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(html_path)
        absolute_html_path = os.path.abspath(html_path)
        file_uri = Path(absolute_html_path).as_uri()
        bot_thread = threading.Thread(target=visit_and_cleanup_html, args=(file_uri, html_path))
        bot_thread.start()

        return "Your application has been submitted for review!"

    return render_template('index.html', difficulty=POW_DIFFICULTY)

@app.route('/flagdb')
def flag_database():
    if request.remote_addr != '127.0.0.1':
        abort(403, "Forbidden: This resource is only accessible from localhost.")
    allowed_hosts = ['127.0.0.1:1337', 'localhost:1337']
    if request.host not in allowed_hosts:
        abort(403, "Forbidden: Invalid Host header.")
    if request.headers.get('Sec-Fetch-Site') == 'cross-site' and request.headers.get('Sec-Fetch-Mode') != 'navigate':
        abort(403, "Forbidden: This resource is not accessible through fetch.")
    
    query_id = request.args.get('id', '1')
    try:
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE flags (id INTEGER PRIMARY KEY, flag TEXT NOT NULL)')
        cursor.execute("INSERT INTO flags (id, flag) VALUES (?, ?)", (1, FLAG))
        conn.commit()
        query = f"SELECT flag FROM flags WHERE id = {query_id}"
        result = cursor.execute(query).fetchone()
        conn.close()

        response = make_response("ok")
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
        return response
    except Exception as e:
        return f"Database error: {e}", 500

@app.route('/healthz', methods=['GET'])
def healthcheck():
    return "OK"

if __name__ == '__main__':
    pow_clear_thread = threading.Thread(target=clear_pow_set_periodically, daemon=True)
    pow_clear_thread.start()
    app.run(host='0.0.0.0', port=1337)