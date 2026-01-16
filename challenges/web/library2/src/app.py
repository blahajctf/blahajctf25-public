import os
import hashlib
import subprocess
import shutil
import threading
import time
import tempfile
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory, abort, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)
POW_DIFFICULTY = 5
POW_CLEAR_INTERVAL_SECONDS = 30
CHROMIUM_TIMEOUT = 60
USED_POW_HASHES = set()

def clear_pow_set_periodically():
    global USED_POW_HASHES
    while True:
        time.sleep(POW_CLEAR_INTERVAL_SECONDS)
        USED_POW_HASHES.clear()

def admin_bot_visit(url):
    temp_dir = None
    chromium_path = shutil.which('chromium-browser') or shutil.which('chromium')
    if not chromium_path:
        print("[!] ERROR: Chromium not found. Cannot visit URL.")
        return
    print(f"[*] The Head Librarian is visiting: {url}")
    try:
        temp_dir = tempfile.mkdtemp()
        cmd = [
            chromium_path, '--disable-gpu', '--no-sandbox', '--headless',
            '--disable-popup-blocking', f'--user-data-dir={temp_dir}', url
        ]
        subprocess.run(cmd, timeout=CHROMIUM_TIMEOUT, check=True, capture_output=True)
        print(f"[*] Visit complete for: {url}")
    except subprocess.TimeoutExpired:
        print(f"[!] Visit timed out for: {url}")
    except Exception as e:
        print(f"[!] Error during visit: {e}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') != 'admin' or request.remote_addr != '127.0.0.1':
            return render_template('error.html', message="Forbidden: You lack the authority to view these sacred texts."), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/motd')
def motd():
    messages = [
        "The journey of a thousand miles begins with a single step. - Laozi",
        "To know what you know and what you do not know, that is true knowledge. - Confucius",
        "He who is contented is rich. - Laozi"
    ]
    return jsonify(messages)

@app.route('/')
def index():
    return render_template('index.html', difficulty=POW_DIFFICULTY)

@app.route('/submit_scripture', methods=['POST'])
def submit_scripture():
    pow_solution = request.form.get('pow_solution')
    if not pow_solution:
        return render_template('index.html', difficulty=POW_DIFFICULTY, error="The Gatekeeper requires a solution.")
    solution_hash = hashlib.sha256(pow_solution.encode()).hexdigest()
    if solution_hash in USED_POW_HASHES:
        return render_template('index.html', difficulty=POW_DIFFICULTY, error="This seal has already been used.")
    if not solution_hash.startswith('0' * POW_DIFFICULTY):
        return render_template('index.html', difficulty=POW_DIFFICULTY, error="Invalid solution. The elders are not appeased.")
    USED_POW_HASHES.add(solution_hash)
    url = request.form.get('url')
    if not url or not url.lower().endswith('.pdf'):
        return render_template(
            'index.html', 
            difficulty=POW_DIFFICULTY, 
            error="Submission rejected. Only true scrolls (URLs ending in .pdf) are accepted."
        )
    submitter = session.get('username', 'An anonymous scholar')
    bot_thread = threading.Thread(target=admin_bot_visit, args=(url,))
    bot_thread.start()
    
    return render_template('index.html', difficulty=POW_DIFFICULTY, message="The Head Librarian is reviewing your scroll now.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if request.remote_addr == '127.0.0.1':
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials. The elders are displeased.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/scriptures')
@admin_required
def list_scriptures():
    scripture_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scriptures')
    if not os.path.exists(scripture_path):
        os.makedirs(scripture_path)
    files = [f for f in os.listdir(scripture_path) if f.endswith('.pdf')]
    return render_template('scriptures.html', files=files)

@app.route('/scriptures/<path:filename>')
@admin_required
def get_scripture(filename):
    sec_fetch_site = request.headers.get('Sec-Fetch-Site')
    sec_fetch_mode = request.headers.get('Sec-Fetch-Mode')
    if sec_fetch_site == 'cross-site' or sec_fetch_mode != 'navigate':
        abort(403)
    return send_from_directory('scriptures', filename, as_attachment=False, conditional=False)

if __name__ == '__main__':
    pow_thread = threading.Thread(target=clear_pow_set_periodically, daemon=True)
    pow_thread.start()
    app.run(host='0.0.0.0', port=1337)