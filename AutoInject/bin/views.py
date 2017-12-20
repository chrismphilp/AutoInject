import pymongo, json

from json import loads
from bson.json_util import dumps
from flask import Flask, render_template, request
from pymongo import MongoClient

from AutoInject import app

import AutoInject.bin.get_Vulnerabilities as gv

client                  = MongoClient()

# @app.route("/")
# def index():  
#     insert_Packages()
#     package_JSON_data = get_Packages_JSON()
#     return render_template('index.html', package_JSON_data=package_JSON_data)

@app.route("/vulnerabilities")
def vulnerabilities():
    vulnerability_JSON_data = gv.return_Matched_Vulnerability_Values()
    return render_template('vulnerabilities.html', vulnerability_JSON_data=vulnerability_JSON_data)

@app.route("/vulnerabilities/<package>")
def return_CVE_IDs(package):
	print(package)
	package_collection 	= client['package_db']['package_list']
	cursor				= package_collection.find( { 'formatted_package_name_with_version' : package } )

	list_Of_Values 		= []
	for values in cursor:
		list_Of_Values.extend(values['matching_ids'])
	print(list_Of_Values)

	cve_collection 		= client['cvedb']['cves']
	vulnerabilities 	= loads(dumps( cve_collection.find( { 'id' : { '$in' : list_Of_Values } } ) ))
	print(vulnerabilities)

	return render_template('individual_package.html', vulnerabilities=vulnerabilities)

@app.route("/profile")
def profile():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template('index.html')