import pymongo, re, time, sys
import multiprocessing as mp
import get_Packages as gp

from pymongo import MongoClient
from json import loads
from bson.json_util import dumps
from subprocess import check_output

# client                  = MongoClient()
# db                      = client['cvedb']
# collection              = db['cves']

list_Of_Memes = []

def get_Vulnerabilities():

    global package_Names_With_Versions, system_Vulnerabilites_IDs
    system_Vulnerabilites_IDs   = []

    for elem in collection.find({}):
        system_Vulnerabilites.append(
            { 
                'id' : elem['id'], 
                'vulnerable_systems' : elem['vulnerable_configuration'],
                'references' : elem['references'], 
                'summary' : elem['summary']
            }
        )

def run_Vulnearbility_Search():

    for value in gp.package_Names_With_Versions:
        out                 = check_output(["../../../cve-search/bin/search.py", "-p", value, "-o", "json"], 
                                universal_newlines=True)
        tmp                 = out.split('\n')

def search_Database(package_Array):

    client                  = MongoClient()
    db                      = client['cvedb']
    collection              = db['cves']

    # regx = re.compile("python:3.4.0$")
    # reg2 = re.compile(".*python:3.4.0.*")

    # cursor = collection.find( { 'vulnerable_configuration' : re.compile("python:3.4.0$") } )
    # cursor2 = collection.find( { 'vulnerable_configuration' : { '$regex' : ('python:3.4.0$'), '$options' : 'i' } } )
    
    # count = 0
    # start = time.time()
    # for values in cursor:
    #     if (count == 0): print(values)
    #     count += 1
    # end = time.time()
    # print("Total time: ", end - start)
    # count = 0
    # start2 = time.time()
    # for values in cursor2:
    #     if (count == 0): print(values)
    #     count += 1
    # end2 = time.time()
    # print("Total time 2: ", end2 - start2)

    # for items in package_Array:
    #     print('$' + items)

    #     cursor = collection.find( { 'vulnerable_configuration' : re.compile(items + "$") } )

    #     for inner_items in cursor:
    #         list_Of_Memes.append(inner_items['id'])
    #     print('Finished sorting:', items)
        # sys.stdout.flush()

    # print(package_Array)
    list_Of_Regex = ""
    count = 0
    for items in package_Array:
        if count == 0:
            list_Of_Regex += (':' + items + '$')
            count += 1
        elif count < 500: 
            list_Of_Regex += (' | :' + items + '$')
            count += 1
        else:
            regx = re.compile(list_Of_Regex)
            cursor = collection.find( { 'vulnerable_configuration' : regx } )
            print(list_Of_Regex, '\n')
            list_Of_Regex = ""
            count = 0
            for items in cursor:
                print(items)
                print()

    # print(list_Of_Regex)
    # regx = re.compile(list_Of_Regex)
    # cursor = collection.find( { 'vulnerable_configuration' : regx } )

    # cursor      = collection.find( 
    #     {
    #         '$or' : list_Of_Regex
    #     }
    # )


    # try:
    #     collection.drop_index(index)
    # except:
    #     print("Index doesn't exist")

    # collection.create_index(index)
    # cursor = index.find( {'$text' : { '$search' : "python"}} )
    # cursor = collection.find( { 'vulnerable_configuration_1': { '$search' : "python:3.4.0" } } )

    # for values in cursor:
    #     try:    
    #         print('\n')
    #         print(values['id'])
    #     except:
    #         print("Couldn't print out:", values)

    # print("Total time: ", end - start)

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

gp.insert_Packages()
# process_Creator()
search_Database(gp.package_Names_With_Versions)
# print(list_Of_Memes)

# print(mp.cpu_count())