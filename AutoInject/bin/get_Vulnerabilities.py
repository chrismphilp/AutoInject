import pymongo, re, time, sys
import multiprocessing as mp
import get_Packages as gp

from pymongo import MongoClient
from json import loads
from bson.json_util import dumps
from subprocess import check_output

client                  = MongoClient()
db                      = client['cvedb']
collection              = db['cves']

list_Of_CVE_IDs         = []

def search_Database(name_Array, name_With_Version_Array):

    start1 = time.time()
    
    for values in name_Array:
        cursor = collection.find( { '$text' : { '$search' : values } } )        
        for items in cursor:
            try:    
                if items['id'] not in list_Of_CVE_IDs:
                    list_Of_CVE_IDs.append(items['id'])
            except:
                print("Couldn't print out:", items)
    
    end1 = time.time()

    print("Time to search packages: ", end1 - start1)  
    print('Number of CVE IDs:', len(list_Of_CVE_IDs))

    start2 = time.time()

    for values in name_With_Version_Array:
        cursor = collection.find( 
            {
                '$text' : { '$search' : "\"" + values + "\""},
                'id' : { '$in' : list_Of_CVE_IDs } 
            }
        )
        # for items in cursor:

    end2 = time.time()
    print("Time to match exact package names:", end2 - start2)

    # cursor = collection.find( {'$text' : { '$search' : "python"} } )

def match_Vulnerabilites_To_Packages():



def initial_Update_Database():

    collection.update( 
        {},
        { '$set' : { 'matched_To_CVE' : 0 } },
        upsert=False,
        multi=True 
    )

def process_Creator():

    start = time.time()

    pool = mp.Pool(processes=8)
    pool.map(search_Database, chunks(gp.package_Names_With_Versions))
    pool.close()
    pool.join()

    end = time.time()
    print("Total time: ", end - start)

def chunks(array):

    for i in range(0, len(array), 200):
        yield array[i : i + 200]

initial_Update_Database()
# gp.insert_Packages()
# search_Database(gp.package_Names, gp.package_Names_With_Versions)