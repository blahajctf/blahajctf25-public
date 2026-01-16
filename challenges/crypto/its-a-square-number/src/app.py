from flask import Flask, render_template, request, redirect, url_for, session
from Crypto.Util.number import getPrime
import random
from os import urandom

from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import InputRequired, NumberRange

flag = 'blahaj{4ny0n3l1v3d1n4pr3ttyh0wt0wn}'

def generate_problem():
    p, q = getPrime(64), getPrime(64)
    modulus = p*q
    answer = random.getrandbits(123)
    question = pow(answer, 2, modulus)
    return answer, question, modulus 

def check_problem(answer, question, modulus):
    return pow(question, 2, modulus) == answer

class AnswerForm(FlaskForm):
    answer = IntegerField(
        'Answer',
        validators=[
            InputRequired(message="◩ Answer is required! ◪"),
            NumberRange(min=0, max=2**130, message=f"◩ Your number's too big! ◪")
        ]
    )
    submit = SubmitField('⬚ Submit ⬚')

app = Flask(__name__)
app.config['SECRET_KEY'] = urandom(64)

@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    if request.method == 'POST':
        answer = int(request.form.get('answer'))
        modulus = session['modulus']
        question = session['question']
        if pow(answer, 2, modulus) == question:
            return render_template('flag.html', flag=flag)
        else:
            message = "NOT SQUARE..."
    answer, question, modulus = generate_problem()
    session['question'] = question
    session['modulus'] = modulus
    print(answer)
    return render_template('square.html', form=AnswerForm(), question=question, modulus=modulus, message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
