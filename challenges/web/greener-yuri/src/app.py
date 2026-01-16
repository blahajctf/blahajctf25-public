from flask import Flask, render_template, session, request
from os import urandom

app = Flask(__name__)
app.config['SECRET_KEY'] = urandom(64)

fake_song_names = [
    "Subselachian Homesick Alien",
    "About A Shark",
    "Here Come The White Sharks",
    "The Power of Independent Sharking",
    "Washing Machine Shark",
    "Shark's End Dancehall",
    "Breadchum Trail",
    "Fin Shaped Box",
    "Finless Apprentice",
    "Born Under Water (The Gills Go On)",
    "Something Cartilaginous",
    "Orcas in Camo",
    "Sharks in the Bronx",
    "Shark with Basket of Chum",
    "The Sharktacular Commodity",
    "Sharkyon (Death Yon)",
    "Anthems For A Seventeen Year Old Selachimorph",
    "Come Out and Swim",
    "Never Fight a Shark With a Perm",
    "Cosmic Shark Seeking Forever", 
    "Big Shark With A Gun",
    "Blahaj Built My Hotrod",
    "Welcome to the Shark Parade",
    "Anyshark Can Play Guitar",
    "They Swim on Tracks of Never-Ending Light",
    "Bed Full of Sharks",
    "Ov Sharkrament and Sincest",
    "The Devil in Sharkskin",
    "Counting Sharks"
]

def f(string):
    return "".join([a.lower() for a in string if a in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'])

@app.route('/', methods=["GET", "POST"])
def main():
    try:
        if request.method == 'POST':
            k = ''
            for i in range(1, 11):
                v = f'song_{i}'
                if f(session[v]) != f(request.form[v]):
                    print(v, session[v], request.form[v])
                    return render_template('index.html', message="It doesn't seem like you're a real fan...")
                return render_template('index.html', message="Here's your promo code: blahaj{l0ve_1n_th3_d33p_s34}")
        
        import random
        songs = random.sample(fake_song_names, k=10)
        for i in range(1, 11):
            session[f'song_{i}'] = songs[i-1]
        return render_template('index.html')
    except: return render_template('index.html')

@app.route('/healthz', methods=['GET'])
def healthcheck():
    return "OK"

if __name__ == "__main__":
    app.run(host='0.0.0.0')
