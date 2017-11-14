import pymongo
from pymongo import MongoClient
import pprint

client      = MongoClient()
db          = client['cvedb']
cve_data    = db.cves

for data in cve_data.find({"vulnerable_configuration": "ubuntu"}):
    pprint.pprint(data)
