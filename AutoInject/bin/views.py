import pymongo
from AutoInject import app
from flask import Flask, render_template, request
from pymongo import MongoClient



@app.route("/")
def index():
    return render_template('index.html')

@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template('index.html')

@app.route("/profile")
def profile():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template('index.html')