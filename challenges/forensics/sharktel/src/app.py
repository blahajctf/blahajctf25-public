from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)

USERNAME = "djungelskog"
PASSWORD = "sh4rk0m0de"

@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        name = request.form.get("name", "")
        pswd = request.form.get("pswd", "")
        if name == USERNAME and pswd == PASSWORD:
            return render_template("flag.html")
        else:
            error = "Invalid username or password"
    return render_template("index.html", error=error)

@app.route("/healthz", methods=["GET"])
def healthcheck():
    return "OK"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

