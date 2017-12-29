import pymongo, json, datetime

from json import loads
from bson.json_util import dumps
from flask import Flask, render_template, request, redirect
from pymongo import MongoClient

from AutoInject import app

import AutoInject.bin.get_Vulnerabilities as gv
import AutoInject.bin.get_Packages as gp
import AutoInject.bin.system_functions as sf

client                  = MongoClient()
package_collection      = client['package_db']['package_list']
cve_collection          = client['cvedb']['cves']
current_time            = datetime.datetime.now().time()

@app.route("/")
def index():  
    package_JSON_data = gp.get_Package_Data()
    return render_template('index.html', package_JSON_data=package_JSON_data)

@app.route("/drop")
def drop():  
    print("Hello drop")
    
    cve_collection.update( 
        {}, 
        { '$unset' : { 'matched_To_CVE' : 1 } }, 
        multi=True 
    )
    package_JSON_data = gp.get_Package_Data()
    gp.insert_Packages(package_JSON_data)
    gv.remove_Special_Characters()
    gv.collect_Checkable_Packages()
    return redirect("/", code=302)

@app.route("/refresh")
def refresh():  
    print("Refresh time")
    gv.run_Database_Updater_Script()
    gv.remove_Special_Characters()
    return redirect("/", code=302)

@app.route("/vulnerabilities")
def vulnerabilities():

    vulnerability_JSON_data = gv.return_Matched_Vulnerability_Values()
    return render_template('vulnerabilities.html', vulnerability_JSON_data=vulnerability_JSON_data)

@app.route("/vulnerabilities/<package>")
def return_CVE_IDs(package):

    cursor          = package_collection.find( { 'formatted_package_name_with_version' : package } )

    list_Of_Values  = []
    for values in cursor:
        list_Of_Values.extend(values['matching_ids'])

    vulnerabilities = loads(dumps( cve_collection.find( { 'id' : { '$in' : list_Of_Values } } ) ))
    return render_template('individual_package.html', vulnerabilities=vulnerabilities, package=package)

@app.route("/profile")
def profile():
    return render_template('profile.html')

@app.route("/about")
def about():
    return render_template('about.html')
