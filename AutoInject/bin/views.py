from AutoInject import app
from flask import Flask, render_template, request

@app.route("/")
def index():
    return render_template('index.html')