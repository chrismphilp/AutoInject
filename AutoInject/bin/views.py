import pymongo
from AutoInject import app
from flask import Flask, render_template, request
from pymongo import MongoClient

from AutoInject.bin import get_Packages

@app.route("/")
def index():
    insert_Packages()
    package_JSON_data = get_Packages_JSON()
    return render_template('index.html', package_JSON_data)

@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template('index.html')

@app.route("/profile")
def profile():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template('index.html')