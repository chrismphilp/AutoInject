import sys

from flask import Flask, render_template, request
app = Flask(__name__)

@app.route("/")
def index():
    return render_template('layout.html')

app.debug = True
if __name__ == "__main__":
    app.run()