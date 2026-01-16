# NOTE: please access the url in your browser with HTTPS

# openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -sha256 -days 365 -subj "/CN=blahaj"
# hypercorn app:asgi_app --bind "127.0.0.1:8000" --keyfile key.pem --certfile cert.pem

import os
import sqlite3, threading
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, g, session
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = 'database.db'
SECRET_KEY = '' # this is different in prod

DB_SCHEMA = """
DROP TABLE IF EXISTS user;
CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  cash INTEGER NOT NULL DEFAULT 0,
  gift_card_state INTEGER NOT NULL DEFAULT 1
);
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.cursor().executescript(DB_SCHEMA)
        db.commit()
        print("Initialized the database.")

@app.before_request
def before_request():
    if not os.path.exists(DATABASE):
        init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to view this page.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    if user_id is None:
        return dict(user=None)
    db = get_db()
    user_data = db.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    return dict(user=user_data)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        if db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone():
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.execute('INSERT INTO user (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_data = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()
        
        if user_data is None or not check_password_hash(user_data['password'], password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
        
        session.clear()
        session['user_id'] = user_data['id']
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

def redeem(user_id):
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    user_data = db.execute('SELECT cash, gift_card_state FROM user WHERE id = ?', (user_id,)).fetchone()
    if user_data['gift_card_state'] == 1:
        new_cash = user_data['cash'] + 500
        db.execute('UPDATE user SET cash = ? WHERE id = ?', (new_cash, user_id))
        db.commit()
        db.execute('UPDATE user SET gift_card_state = 0 WHERE id = ?', (user_id,))
        db.commit()

@app.route('/use_gift_card', methods=['POST'])
@login_required
def use_gift_card():
    user_id = session['user_id']
    threading.Thread(target = redeem, args = (user_id,)).start()
    flash('Request to redeem has been sent.', 'success')
    return redirect(url_for('index'))

@app.route('/flag')
@login_required
def get_flag():
    return render_template('flag.html')

from asgiref.wsgi import WsgiToAsgi
asgi_app = WsgiToAsgi(app)