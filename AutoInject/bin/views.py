import pymongo, json

from json import loads
from bson.json_util import dumps
from flask import Flask, render_template, request, redirect
from pymongo import MongoClient

from AutoInject import app

import AutoInject.bin.get_Vulnerabilities as gv
import AutoInject.bin.get_Packages as gp

client                  = MongoClient()
package_collection      = client['package_db']['package_list']
cve_collection          = client['cvedb']['cves']

@app.route("/")
def index():  

    package_JSON_data = gp.get_Package_Data()

    if (request.args.get('package_drop')):
        print("Holla")
        package_collection.delete_many({})
        cve_collection.update( 
            {}, 
            { '$unset' : { 'matched_To_CVE' : 1, 'reformatted_configs' : 1 } }, 
            upsert=True, 
            multi=True 
        )
        gp.insert_Packages(package_JSON_data)
        gv.remove_Special_Characters()
        gv.collect_Checkable_Packages()
        request.args = { 'package_drop' : False }
        redirect("/", code=302)
        return render_template('index.html', package_JSON_data=package_JSON_data)
    else: 
        return render_template('index.html', package_JSON_data=package_JSON_data)

@app.route("/vulnerabilities")
def vulnerabilities():

    vulnerability_JSON_data = gv.return_Matched_Vulnerability_Values()
    return render_template('vulnerabilities.html', vulnerability_JSON_data=vulnerability_JSON_data)

@app.route("/vulnerabilities/<package>")
def return_CVE_IDs(package):

    cursor              = package_collection.find( { 'formatted_package_name_with_version' : package } )

    list_Of_Values      = []
    for values in cursor:
        list_Of_Values.extend(values['matching_ids'])

    vulnerabilities     = loads(dumps( cve_collection.find( { 'id' : { '$in' : list_Of_Values } } ) ))
    return render_template('individual_package.html', vulnerabilities=vulnerabilities, package=package)

@app.route("/profile")
def profile():
    return render_template('profile.html')

@app.route("/about")
def about():
    return render_template('about.html')
