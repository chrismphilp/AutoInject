import pymongo, json
from AutoInject import app
from flask import Flask, render_template, request
from pymongo import MongoClient

from AutoInject.bin.get_Vulnerabilities import *

@app.route("/")
def index():
    insert_Packages()
    package_JSON_data = get_Packages_JSON()
    return render_template('index.html', package_JSON_data=package_JSON_data)

@app.route("/vulnerabilities")
def vulnerabilities():
    vulnerability_JSON_data = get_Vulnerabilities()
    return render_template('vulnerabilities.html', vulnerability_JSON_data=vulnerability_JSON_data)

@app.route("/profile")
def profile():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template('index.html')