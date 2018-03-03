import  pymongo, re, time

import  AutoInject.bin.system_Functions as sf

from    json                            import loads
from    bson.json_util                  import dumps
from    pymongo                         import MongoClient
from    subprocess                      import check_output

client                      = MongoClient()
db                          = client['package_db']
collection                  = db['package_list']

def get_Package_Data():
    
    tmp = check_output(
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"], 
        universal_newlines=True
    ).split('\n')
    
    print('Retrieving list of packages on system')
    list_to_insert              = []
    package_names_with_versions = []
    for line in tmp:
        package_array = line.split('\t')

        try:
            package_version                         = sf.get_Formatted_Version(package_array[1])
            formatted_package_name_without_version  = sf.get_Formatted_Name(package_array[0])
            squashed_version                        = ''.join(e for e in package_version if e.isalnum())
            package_name_with_version               = formatted_package_name_without_version + squashed_Version
            squashed_name_with_version              = ''.join(e for e in package_name_with_version if e.isalnum() or e == ':')

            package_item = {
                'package_name_with_version' : package_name_with_version,
                'package_name' : package_array[0],
                'formatted_package_name_with_version' :  squashed_name_with_version,
                'formatted_package_name_without_version' : formatted_package_name_without_version,
                'version' : package_version, 
                'formatted_version' : squashed_version,
                'architecture' : package_array[2],
                # 1 = updateable, 0 means do not update
                'updateable' : 1,
                'current_ubuntu_version' : package_array[1],
                'matching_ids' : []
            }
            list_to_insert.append(package_item)
            package_names_with_versions.append(squashed_name_with_version)
        
        except:
            print("Error inserting", package_array)
            continue
    return(list_to_insert, package_names_with_versions)

def insert_Packages(package_List):
    # Deleting any current package details
    db.package_list.drop()
    print('Collection names (should be empty):', db.collection_names())
    collection.insert(package_List)
    print('Finished inserting into DB')

def get_Packages_JSON():
    package_JSON = collection.find({})
    return loads(dumps(package_JSON))
