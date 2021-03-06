import pymongo, re, time, sys, subprocess

from pymongo                            import MongoClient
from json                               import loads
from bson.json_util                     import dumps

import AutoInject.bin.get_Packages      as gp
import AutoInject.bin.system_Functions  as sf

client                      = MongoClient()
cve_collection              = client['cvedb']['cves']
package_collection          = client['package_db']['package_list']

def collect_Checkable_Packages():
    package_Data = gp.get_Package_Data()
    check_For_New_Packages(package_Data)
    check_For_Updated_Packages(package_Data)
    remove_Special_Characters()
    search_New_Vulnerabilities(package_Data)

def check_For_New_Packages(package_data):
    
    print("Attempting to remove indexes")
    try:    cve_collection.drop_index("summary_text")
    except: print("vulnerable_configuration_1 does not exist")
    
    print("Creating index on new values")

    cve_collection.create_index(
        [
            ('id', pymongo.TEXT),
            ("vulnerable_configuration", pymongo.TEXT),
            ("reformatted_configs", pymongo.TEXT) 
        ],
        name="vulnerability_index"
    )
    
    # Find all completely new packages
    print("Getting all newly installed packages")
    list_of_new_packages = []
    for values in package_data[0]:
        if not package_collection.find_one( { 'package_name' : values['package_name'] } ):
            package_collection.insert(values)
            list_of_new_packages.append(values)

    for package_indexes in list_of_new_packages:
        cursor = cve_collection.find( { 
            '$text' : { '$search' : package_indexes['package_index'] },
            'matched_To_CVE' : { '$ne' : 1 } 
        } )

        list_Of_IDs = []
        for values in cursor:
            cve_collection.update(
                { 'id' : values['id'] },
                { '$set' : { 'matched_To_CVE' : 1 } }
            )
            list_Of_IDs.append(values['id'])

        package_collection.update(
            { 'package_index' : package_indexes['package_index'] },
            { '$push' : { 'matching_ids' : { '$each' : list_Of_IDs } } }
        )

def check_For_Updated_Packages(package_data):
    # Use this for package updates, when the squashed_name will have changed, but package is the same 
    print("Getting packages that have been updated")
    for values in package_collection.find( { 'apt_version' : { '$nin' : package_data[2] } } ):
        for items in package_data[0]:
            if items['package_name'] == values['package_name']:
                for ids in values['matching_ids']:
                    cve_collection.update(
                        { 'id' : ids },
                        { '$unset' : { 
                            'matched_To_CVE' : 1, 
                            'matched_to' : 1
                        } }, 
                    )

                current_version = sf.get_Ubuntu_Package_Version(values['package_name'])
                try:
                    package_version             = sf.get_Formatted_Version(current_version)
                    package_name_with_version   = sf.get_Formatted_Name(
                        values['package_name']) + ''.join(e for e in package_version if e.isalnum()
                    )
                    package_index               = ''.join(e for e in package_name_with_version if e.isalnum() or e == ':')
                except: 
                    print("Couln't reformat:", package_name, current_version)

                # Update current package data to match updated values 
                package_collection.update_one(
                    { 'package_name' : values['package_name'] },
                    { '$set' : { 
                        'package_index' : package_index, 
                        'ubuntu_version' : current_version,
                        'apt_version' : values['package_name'] + '=' + current_version,
                        'matching_ids' : []
                    } }
                )

def search_New_Vulnerabilities(package_data):
    # # Search all new packages 
    print('Matching packages to new updated vulnerabilites')
    for package_index in package_data[1]:

        cursor = cve_collection.find( { 
            '$text' : { '$search' : package_index },
            'matched_To_CVE' : { '$ne' : 1 },
            'deleted' : { '$ne' : 1 } }   
        )

        # Create a list to store the list of relating id's to package names
        list_Of_IDs = []
        for values in cursor:
            cve_collection.update(
                { 'id' : values['id'] },
                { '$set' : { 'matched_To_CVE' : 1 } }
            )
            list_Of_IDs.append(values['id'])

        package_collection.update(
            { 'package_index' : package_index },
            { '$push' : { 'matching_ids' : { '$each' : list_Of_IDs } } }
        )

def remove_Special_Characters():
    
    print("Beginning special character removal")
    cursor = cve_collection.find( { 'reformatted_configs' : { '$exists' : False } }, no_cursor_timeout=True)

    for values in cursor:
        list_Of_Reformatted_Configs = format_String(values['vulnerable_configuration'])

        cve_collection.update( 
            { 'id' : values['id'] },
            { '$set' : { 'reformatted_configs' : list_Of_Reformatted_Configs } }
        )
    cursor.close()
    
    print("Attempting to remove indexes")
    try:    cve_collection.drop_index("summary_text")
    except: print("vulnerable_configuration_1 does not exist")
    
    print("Creating index on new values")
    cve_collection.create_index(
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
