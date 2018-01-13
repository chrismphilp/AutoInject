import pymongo, re, time, sys, subprocess

from pymongo import MongoClient
from json import loads
from bson.json_util import dumps

import AutoInject.bin.get_Packages as gp

client                  = MongoClient()
db                      = client['cvedb']
collection              = db['cves']

list_Of_CVE_IDs         = []
global count_Of_Fails
count_Of_Fails          = 0

'''
Order of operations:
    1) run_Database_Updater_Script() getting new packages
    2) remove_Special_Characters() from fields where reformatted_configs does 
        not exist
    3) collect_checkable_packages() which will compare get_Packages() to find 
        which values are not in database against the database. It will then 
        perform a full search against these of all values not with a 
        'matched_CVE_ID' = 1. Then it will run a search of all current packages
        against the new values in the database
    4) update_Database_Matched_Field() will then run, informing the interface all
        values in database currently have been matched
        ### Ensures regular updates ensure optimal performance ###
'''

def run_Database_Updater_Script():
    print("Running script")
    subprocess.call(
        ["python3", "../cve-search/sbin/db_updater.py", "-v"]
    )

def remove_Special_Characters():
    
    global count_Of_Fails
    
    print("Beginning special character removal")
    cursor = collection.find( { 'reformatted_configs' : { '$exists' : False } } )

    for values in cursor:
        list_Of_Reformatted_Configs = format_String(values['vulnerable_configuration'])

        collection.update( 
            { 'id' : values['id'] },
            { '$set' : { 'reformatted_configs' : list_Of_Reformatted_Configs } },
            upsert=False,
            multi=True 
        )

    print("Attempting to remove indexes")
    try:
        collection.drop_index("summary_text")
    except:
        print("vulnerable_configuration_1 does not exist")
    
    print("Creating index on new values")
    collection.create_index(
        [
            ('id', pymongo.TEXT),
            ("vulnerable_configuration", pymongo.TEXT),
            ("reformatted_configs", pymongo.TEXT) 
        ],
        name="vulnerability_index"
    )
    print("Total number of packages unmatchable:", count_Of_Fails)

def format_String(cursor):

    global count_Of_Fails

    word        = re.compile(r'''['a-zA-Z']''')
    re_num      = re.compile(r"""(\d+\.*)+[A-Za-z]*""")
    re_string   = re.compile(r"""(([A-Za-z])+(\-[A-Za-z])*)+""")

    list_Of_Reformatted_Configs = []

    for items in cursor:
            
        split_string = re.split('[:]', items)
        count = 0
        string_At_End = False

        for strings in list(reversed(split_string)):

            if (re.match(re_num, strings)):
                # print('Found a match:', re.match(re_num, strings).group(0))
                temp = re.match(re_num, strings).group(0)
                count += 1
                continue
            if (count == 1):
                name = strings
                break
        try:
            name = ''.join(e for e in name if e.isalnum())
            temp = ''.join(e for e in temp if e.isnumeric())
            list_Of_Reformatted_Configs.append(name + temp)
        except:
            count_Of_Fails += 1
    return list_Of_Reformatted_Configs

def run_Package_Updater():
    gp.get_Packages()

def collect_Checkable_Packages():
    
    '''
    Command to remove updated values:
        coll.update( {}, { '$unset' : { 'matched_To_CVE' : 1, 'reformatted_configs' : 1 } }, { 'multi' : true } )
        coll.update( {}, { '$unset' : { 'reformatted_configs' : 1 } }, { 'multi' : true } )
        coll.update( {}, { '$unset' : { 'matched_To_CVE' : 1 } }, { 'multi' : true } )
    '''

    # Use this for package updates, when the squashed_name will have changed
    package_Collection = client['package_db']['package_list']
    new_Package_Cursor = package_Collection.find(
        { 'formatted_package_name_with_version' : { '$nin' : gp.package_Names_With_Versions } }
    )

    print('Getting new packages and comparing to all values')
    for values in new_Package_Cursor:

        # Find all CVE's that match the new package, not currently matched (not including new found vulnerabilties)
        cursor = collection.find( 
            { 'matched_CVE_ID' : 0 },
            { '$text' : 
                { 
                    '$search' : values['squashed_Name_With_Version'],
                    '$language' : 'none' 
                } 
            } 
        )

        # Create a list to store the list of relating id's to package names
        list_Of_IDs = []
        # For each matched id to package, update the package matched_To_CVE data to 1
        for unsearched_Packages in cursor:
            collection.update(
                { 'id' : unsearched_Packages['id'] },
                { '$set' : { 'matched_To_CVE' : 1, 'matched_to' : values['squashed_Name_With_Version'] } },
                upsert=True,
                multi=True
            )
            list_Of_IDs.append(unsearched_Packages['id'])

        '''
        --- WHAT IF PACKAGE HAS BEEN UPDATED OUTSIDE THE SYSTEM ---
        1) Complete a not in on packages compared to current packages
        2) Find the one with same package_name and delete
        3) Perform a new search with updated package/new package
        '''

        # Need to add new packages to package_db database
        for items in gp.list_To_Insert:
            if (items['squashed_Name_With_Version'] == values['squashed_Name_With_Version']):
                items['matching_ids'] = list_Of_IDs
                package_Collection.insert_one(items)
                break

    # Search all new packages 
    print('Matching packages to new updated vulnerabilites')
    for items in gp.package_Names_With_Versions:
        
        cursor = collection.find( 
            { 
                '$text' : { '$search' : items },
                'matched_To_CVE' : { '$exists' : False } 
            }     
        )

        # Create a list to store the list of relating id's to package names
        list_Of_IDs = []
        for values in cursor:
            
            collection.update(
                { 'id' : values['id'] },
                { '$set' : { 'matched_To_CVE' : 1 } },
                upsert=False,
                multi=True 
            )
            list_Of_IDs.append(values['id'])

        package_Collection.update(
            { 'formatted_package_name_with_version' : items },
            { '$set' : { 'matching_ids' : list_Of_IDs } },
            upsert=True,
            multi=True
        )

def update_Database_Matched_Field():
    # If there is a package that matches, value = 1; else value = 0
    collection.update( 
        { 'matched_To_CVE' : { '$exists' : False } },
        { '$set' : { 'matched_To_CVE' : 0 } },
        upsert=False,
        multi=True 
    )

def return_Matched_Vulnerability_Values():

    package_Collection = client['package_db']['package_list']
    package_Vulnerability_JSON = package_Collection.find( 
        { 
            'matching_ids' : { '$exists' : True, '$not' : { '$size' : 0 } },
            'updateable' : 1
        } 
    )
    return loads(dumps(package_Vulnerability_JSON))
