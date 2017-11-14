import pymongo
import pprint

client  = MongoClient()
db      = client['cvedb']

cve_data    = db.cves
pprint.pprint(cve_data.find_one())
