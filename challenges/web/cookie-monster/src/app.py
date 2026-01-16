from flask import Flask, render_template, request, jsonify, make_response, redirect
import jwt
import datetime
import secrets
from secret import FLAG, ADMIN_USERNAME, ADMIN_PASSWORD

# Initialize Flask app
# template_folder='.' allows Flask to find index.html in the same directory
app = Flask(__name__)

def decode_token(token):
    
    if not token:
        return None
    
    try:
        kid = jwt.get_unverified_header(token).get('kid')
        key = open(kid).read() # Dynamic key loading based on 'kid' header

        # Now you will never get the key
        return jwt.decode(token, key, algorithms=["HS256"])
    except:
        return None

def encode_token(payload, key_path):
    key = open(key_path).read()
    token = jwt.encode(payload, key, algorithm="HS256", headers={"kid": key_path})
    return token

# --- Routes ---

@app.route('/')
def home():
    """Serves the Cookie Monster Blog HTML"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')
    
    if request.method == "POST":
        """Generates a JWT token if credentials are correct"""
        auth = request.get_json()

        if not auth or not auth.get('username') or not auth.get('password'):
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        # Create Token with a random key
        token = encode_token({
            'user': auth.get('username'),
            'admin': auth.get('username') == ADMIN_USERNAME and auth.get('password') == ADMIN_PASSWORD,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
        }, f'secrets/secret_key{secrets.randbelow(10)}')

        res = jsonify({'login': auth.get('username')})
        res.set_cookie('Token', token)
        return res

@app.route('/admin', methods=['GET'])
def admin_portal():
    if 'Token' in request.cookies:
        token = request.cookies.get('Token')
    else: return redirect('/login')

    auth = decode_token(token)
    if not auth:
        return "Me don't know who you are", 401
    
    return render_template('admin.html')

@app.route('/admin/data', methods=['GET'])
def admin_data():
    if 'Token' in request.cookies:
        token = request.cookies.get('Token')
    else: token = None

    auth = decode_token(token)
    if not auth:
        return "Me don't know who you are", 401
    
    return jsonify({
        'posts': [
            {
                "id": 0,
                "title": "Why Oatmeal Raisin is a Betrayal of Trust",
                "tag": "Opinion",
                "tag_color": "bg-grey-100 text-grey-800",
                "date": "30 minutes ago",
            },
            {
                "id": 1,
                "title": "Optimal Dunking Times",
                "tag": "Study",
                "tag_color": "bg-blue-100 text-blue-800",
                "date": "2 hours ago",
            },
            {
                "id": 2,
                "title": "Vegetables: A Conspiracy?",
                "tag": "Warning",
                "tag_color": "bg-orange-100 text-orange-800",
                "date": "1 day ago",
            },
            {
                "id": 3,
                "title": "C is for Cookie",
                "tag": "Guide",
                "tag_color": "bg-green-100 text-green-800",
                "date": "3 days ago",
            },
            {
                "id": 4,
                "title": FLAG if auth.get('admin') else "[ME COOKIE]",
                "tag": "CONFIDENTIAL",
                "tag_color": "bg-red-100 text-red-800",
                "date": "3 days ago",
            }
        ],
        'status': 'Authorized',
        'cookies': 0,
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)