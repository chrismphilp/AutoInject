import pymongo
from AutoInject import app
from flask import Flask, render_template, request
from pymongo import MongoClient

@app.route("/")
def index():
    return render_template('index.html')