import pymongo
from pymongo import MongoClient
from json import loads
from bson.json_util import dumps
from AutoInject.bin.get_Packages import *

client                  = MongoClient()
db                      = client['cvedb']
collection              = db['cves']

global list_Of_Package_Names

def get_Vulnerabilities():

	global list_Of_Package_Names, system_Vulnerabilites
	system_Vulnerabilites = []

	for package in list_Of_Package_Names:	
		
		vulnerability_JSON 	= collection.find({ "vulnerable_configuration" : {'$regex' : ".*" + package + ".*"} })
		system_Vulnerabilites.append(vulnerability_JSON)

	print(len(system_Vulnerabilites))

	# for data in vulnerability_JSON:
	# 	list_Data.append(('ID:', data['id'], ' References:', data['references'], ' Vulnerable Configurations:', data['vulnerable_configuration']))	

	print('Getting vulnerability data')
	# print('List data:', list_Data)
	# return loads(dumps(vulnerability_JSON))

insert_Packages()
get_Vulnerabilities()
