import pymongo, re, time
# Parsing related modules
import lxml.html as lh 
import requests
from urllib.request import urlopen 

from pymongo import MongoClient
from subprocess import check_output
from bs4 import BeautifulSoup

client                      = MongoClient()
package_collection          = client['package_db']['package_list']
cve_collection 				= client['cvedb']['cves']

list_Of_Parsing_Procedures 	= [
	('bugzilla.redhat', re.compile(r""".*bugzilla.redhat.*"""), '//td[@id="field_container_cf_fixed_in"]/text()'),
	('securityfocus', re.compile(r""".*securityfocus.*"""))
]

def search_URL_For_Version_Update(url):
	print('Scanning:', url)
	start 		= time.time()
	page 		= requests.get(url)
	# tree 		= lh.fromstring(page.content)
	# update_name = tree.xpath('//td[@id="field_container_cf_fixed_in"]/text()')
	end 		= time.time()
	print('Total time for requests:', end - start)
	# print(update_name)

	start1 		= time.time()
	page 		= urlopen(url)
	end1 		= time.time()
	print('Time for urllib:', end1 - start1)

def update_Vulnerability_Information():
	pass

def search_URL_For_BFS_Update():
	pass

# search_URL_For_Version_Update('https://bugzilla.redhat.com/show_bug.cgi?id=902998')
# search_URL_For_Version_Update('https://bugzilla.redhat.com/show_bug.cgi?id=1377613')
# search_URL_For_Version_Update('http://www.securityfocus.com/bid/67106')
search_URL_For_Version_Update('http://lists.fedoraproject.org/pipermail/package-announce/2015-May/157387.html')