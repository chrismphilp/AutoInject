import pymongo, re, time, sys, subprocess

from pymongo                        import MongoClient
from json                           import loads
from bson.json_util                 import dumps

import AutoInject.bin.get_Packages  as gp

client                      = MongoClient()
vulnerability_collection    = client['cvedb']['cves']
package_collection          = client['package_db']['package_list']

def collect_Checkable_Packages():
    check_For_New_Packages()
    check_For_Updated_Packages()
    remove_Special_Characters()
    search_New_Vulnerabilities()

def check_For_New_Packages():
    # Find all completely new packages
    print("Getting all newly installed packages")
    list_of_new_packages = []
    for values in gp.get_Package_Data()[0]:
        if not package_collection.find_one( { 'package_name' : values['package_name'] } ):
            package_collection.insert(values)
            list_of_new_packages.append(values)

    for formatted_package_name in list_of_new_packages:
        cursor = vulnerability_collection.find( 
            { 
                '$text' : { '$search' : formatted_package_name['formatted_package_name_with_version'] },
                'matched_To_CVE' : { '$ne' : 1 } 
            }     
        )

        list_Of_IDs = []
        for values in cursor:
            vulnerability_collection.update(
                { 'id' : values['id'] },
                { '$set' : { 'matched_To_CVE' : 1 } }
            )
            list_Of_IDs.append(values['id'])

        package_collection.update(
            { 'formatted_package_name_with_version' : formatted_package_name['formatted_package_name_with_version'] },
            { '$push' : { 'matching_ids' : { '$each' : list_Of_IDs } } }
        )

def check_For_Updated_Packages():
    # Use this for package updates, when the squashed_name will have changed, but package is the same 
    print("Getting packages that have been updated")
    for values in package_collection.find( { 'formatted_package_name_with_version' : { '$nin' : gp.get_Package_Data()[1] } } ):

        for items in gp.get_Package_Data()[1]:
            if items['formatted_package_name_with_version'] == values['formatted_package_name_with_version']:
                changed_package_name = values['formatted_package_name_with_version']
                package_collection.insert_one(values)

        for ids in values['matched_ids']:
            vulnerability_collection.update(
                { 'id' : ids },
                { '$unset' : { 
                    'matched_To_CVE' : 1, 
                    'matched_to' : 1
                } }, 
            )

        package_collection.remove_one( { '_id' : values['_id'] } )

        if changed_package_name:
            cursor = vulnerability_collection.find( 
                { 'matched_CVE_ID' : { '$ne' : 1 } },
                { '$text' : { '$search' : changed_package_name } } 
            )

            list_Of_IDs = []
            for items in cursor:
                vulnerability_collection.update(
                    { 'id' : items['id'] },
                    { '$set' : { 'matched_To_CVE' : 1 } }
                )
                list_Of_IDs.append(items['id'])

            package_collection.update(
                { 'formatted_package_name_with_version' : formatted_package_name['formatted_package_name_with_version'] },
                { '$push' : { 'matching_ids' : { '$each' : list_Of_IDs } } }
            )

def search_New_Vulnerabilities():
    # # Search all new packages 
    print('Matching packages to new updated vulnerabilites')
    for formatted_package_name in gp.get_Package_Data()[1]:

        cursor = vulnerability_collection.find( 
            { 
                '$text' : { '$search' : formatted_package_name },
                'matched_To_CVE' : { '$ne' : 1 } 
            }     
        )

        # Create a list to store the list of relating id's to package names
        list_Of_IDs = []
        for values in cursor:
            vulnerability_collection.update(
                { 'id' : values['id'] },
                { '$set' : { 'matched_To_CVE' : 1 } }
            )
            list_Of_IDs.append(values['id'])

        package_collection.update(
            { 'formatted_package_name_with_version' : formatted_package_name },
            { '$push' : { 'matching_ids' : { '$each' : list_Of_IDs } } }
        )

def hard_Reset_Packages():
    package_collection.remove({})
    vulnerability_collection.update(
        {},
        { '$unset' : { 
            'matched_To_CVE' : 1, 
            'matched_to' : 1
        } },
        multi=True
    )
    package_JSON_data = gp.get_Package_Data()[0]
    gp.insert_Packages(package_JSON_data)
    remove_Special_Characters()
    search_New_Vulnerabilities()

def remove_Special_Characters():
    
    print("Beginning special character removal")
    cursor = vulnerability_collection.find( { 'reformatted_configs' : { '$exists' : False } } )

    for values in cursor:
        list_Of_Reformatted_Configs = format_String(values['vulnerable_configuration'])

        vulnerability_collection.update( 
            { 'id' : values['id'] },
            { '$set' : { 'reformatted_configs' : list_Of_Reformatted_Configs } },
            upsert=False,
            multi=True 
        )

    print("Attempting to remove indexes")
    try:    vulnerability_collection.drop_index("summary_text")
    except: print("vulnerable_configuration_1 does not exist")
    
    print("Creating index on new values")
    vulnerability_collection.create_index(
        [
            ('id', pymongo.TEXT),
            ("vulnerable_configuration", pymongo.TEXT),
            ("reformatted_configs", pymongo.TEXT) 
        ],
        name="vulnerability_index"
    )

def format_String(cursor):

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
            print("Failure")
    return list_Of_Reformatted_Configs

def return_Matched_Vulnerability_Values():

    package_collection = client['package_db']['package_list']
    package_Vulnerability_JSON = package_collection.find({ 
        'matching_ids' : { '$exists' : True, '$not' : { '$size' : 0 } },
        'updateable' : 1
    })
    return loads(dumps(package_Vulnerability_JSON))

def run_Database_Updater_Script():
    print("Running script")
    subprocess.call(["python3", "../cve-search/sbin/db_updater.py", "-v"])
