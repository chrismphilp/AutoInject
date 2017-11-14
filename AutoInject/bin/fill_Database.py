import pymongo
from pymongo import MongoClient
import pprint

client      = MongoClient()
db          = client['cvedb']
cve_data    = db.cves

count = 0

for data in cve_data.find({"vulnerable_configuration": { '$regex' : "windows" }}):
    if (count > 4): break
	pprint.pprint(data)
	count += 1
