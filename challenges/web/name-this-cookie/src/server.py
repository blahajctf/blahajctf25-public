from flask import Flask, make_response, request
from bot import bot_visit

app = Flask(__name__)

@app.get('/')
def index():
    flag = request.cookies.get('flag', 'Set the `flag` cookie first!')
    return f'Your flag: {flag}'

@app.get('/set-cookie')
def set_cookie():
    name, value = request.args['name'], request.args['value']
    if name.strip().startswith('flag'):
        return 'Be more original', 400

    resp = make_response('Done!')
    resp.set_cookie(name, value, httponly=True)
    return resp

@app.post('/visit')
def visit_endpoint():
    if 'cookie_name' not in request.args:
        return 'Please name your cookie first!', 400

    bot_visit(request.args['cookie_name'])

    return "Thanks for naming my cookie :)"

app.run(host="0.0.0.0", port=5000)
