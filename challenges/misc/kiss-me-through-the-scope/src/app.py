from flask import Flask, url_for, render_template, session, redirect, send_file, request, flash, get_flashed_messages
from PIL import Image, ImageDraw, ImageFont
import os
import hashlib
import io
import random

app = Flask(__name__)
app.secret_key = os.urandom(64)
otp_base = 'static/otp_base.png'

font = ImageFont.truetype('static/Consolas.ttf', 60)

def gen_key(otp: int):
    return hashlib.sha256(
        str(otp).encode() + app.secret_key
    ).hexdigest()

def get_otp_from_key(hashvalue: str):
    for i in range(0, 10000):
        if gen_key(i) == hashvalue:
            return i

def generate_otp_img(otp: int):
    otp_img = Image.open(otp_base)
    text_img = ImageDraw.Draw(otp_img)
    otp_str = str(otp).zfill(4)
    text_img.text((77, 32),  otp_str[0], fill=(0, 0, 0), font=font)
    text_img.text((161, 32), otp_str[1], fill=(0, 0, 0), font=font)
    text_img.text((245, 32), otp_str[2], fill=(0, 0, 0), font=font)
    text_img.text((329, 32), otp_str[3], fill=(0, 0, 0), font=font)
    return otp_img

default_vals = dict()
for i in range(1, 13):
    default_vals[f'x{i}'] = ''
    default_vals[f'y{i}'] = ''

def make_new_otp(session):
    otp = random.randint(1000, 9999)
    session['otp_key'] = gen_key(otp)
    print(f'generated new {otp = }')    


@app.route('/')
def main():
    if 'round' not in session:
        session['round'] = 1
        session['checked'] = 0
        make_new_otp(session)
    
    return render_template('base.html',
                           round=session['round'],
                           results=[
                                '???' for _ in range(12)
                           ],
                           messages = get_flashed_messages(),
                           prev_vals = default_vals,
                           checks = session['checked']
                           )

@app.route('/otp_generate')
def generate():
    img = generate_otp_img(random.randint(1000, 9999))
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    print(img_io)
    return send_file(img_io, mimetype='image/png')

@app.route('/check_values', methods=['POST'])
def check_values():

    if 'otp_key' not in session:
        return redirect(url_for('main'))

    if session['checked'] == 12:
        flash('YOU HAVE ALREADY GOTTEN YOUR TWELVE PIXEL VALUES.')
        return redirect(url_for('main'))
    
    current_otp = get_otp_from_key(session['otp_key'])
    img = generate_otp_img(current_otp)

    prev_vals = dict()
    if 'results' not in session:
        session['results'] = [None for i in range(12)]
    
    print(session['results'])
    new_results = []
    
    for i in range(1, 13):
        x = request.form.get(f'x{i}')
        y = request.form.get(f'y{i}')
        prev_vals[f'x{i}'] = x
        prev_vals[f'y{i}'] = y

        try:
            x, y = int(x), int(y)
            r, g, b = img.getpixel((x, y))
            hex_val = f"#{r:02x}{g:02x}{b:02x}"
            print(x, y, hex_val)
            found = False
            if session['results'][i-1]:
                found_x, found_y, new_hex_val = session['results'][i-1]
                if found_x == x and found_y == y and new_hex_val[0] == '#':
                    found = True
            if not found:
                session['checked'] = session['checked'] + 1 
        except Exception as e:
            import traceback; traceback.print_exc()
            hex_val = "ERROR"
        
        new_results.append((x, y, hex_val))

    session['results'] = new_results

    return render_template('base.html',
                        round=session['round'],
                        results=session['results'],
                        messages = get_flashed_messages(),
                        prev_vals = prev_vals,
                        checks = session['checked']
                        )

@app.route('/guess_otp', methods=['POST'])
def guess_otp():
    if 'otp_key' not in session:
        return redirect(url_for('main'))

    guess = request.form.get('guess')
    session['checked'] = 0
    try:
        guess = int(guess)
        print('correct otp > ', get_otp_from_key(session['otp_key']))
        if gen_key(guess) == session['otp_key']:
            session['round'] = session['round'] + 1
            if session['round'] == 4:
                return send_file('flag.jpg') 
            else:
                flash(f"THAT WAS A CORRECT OTP! YOU ARE NOW IN ROUND {session['round']}.");
                make_new_otp(session)
                return render_template('base.html',
                                    round=session['round'],
                                    results=[
                                            '???' for _ in range(12)
                                    ],
                                    messages = get_flashed_messages(),
                                    prev_vals = default_vals,
                                    success=True,
                                    checks=session['checked']
                                    )
        else: raise Exception('wrong otp!')
    except:
        session['round'] = 1
        flash(f"THAT WAS THE WRONG OTP. YOU ARE NOW BACK IN ROUND 1.")
        make_new_otp(session)
        return render_template('base.html',
                    round=session['round'],
                    results=[
                            '???' for _ in range(12)
                    ],
                    messages = get_flashed_messages(),
                    prev_vals = default_vals,
                    checks=session['checked']
                    )
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1337)
