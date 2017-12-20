import pymongo, re, time
from json import loads
from bson.json_util import dumps
from pymongo import MongoClient
from subprocess import check_output

client                  = MongoClient()
db                      = client['package_db']
collection              = db['package_list']

package_Names_With_Versions = []
list_To_Insert              = []

def get_Package_Data():

    out                 = check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"], 
                            universal_newlines=True)
    tmp                 = out.split('\n')
    
    print('Retrieving list of packages on system')
    for line in tmp:
        package_array   = line.split('\t')

        try:
            package_Version                         = get_Formatted_Version(package_array[1])
            formatted_Package_Name_Without_Version  = get_Formatted_Name(package_array[0])
            squashed_Version                        = ''.join(e for e in package_Version if e.isalnum())
            package_Name_With_Version               = formatted_Package_Name_Without_Version + squashed_Version
            squashed_Name_With_Version              = ''.join(e for e in package_Name_With_Version if e.isalnum())

            package_item = {
                'package_name_with_version' : package_Name_With_Version,
                'package_name' : package_array[0],
                'formatted_package_name_with_version' :  squashed_Name_With_Version,
                'formatted_package_name_without_version' : formatted_Package_Name_Without_Version,
                'version' : package_Version,
                'formatted_version' : squashed_Version,
                'architecture' : package_array[2]
            }
            list_To_Insert.append(package_item)
            package_Names_With_Versions.append(squashed_Name_With_Version)
        
        except:
            print("Error inserting", package_array)
            continue
    return(list_To_Insert)

def insert_Packages(package_List):

    # Deleting any current package details
    db.package_list.drop()
    print('Collection names (should be empty):', db.collection_names())
    collection.insert(list_To_Insert)
    print('Finished inserting into DB')

def get_Formatted_Name(package_Name):

    re_string = re.compile(r"""(([A-Za-z])+(\-[A-Za-z])*)+""")
    return (re.match(re_string, package_Name)).group(0)

def get_Formatted_Version(package_Version):

    re_num = re.compile(r"""([0-9]\.*)+""")
    return (re.match(re_num, package_Version)).group(0)

def get_Packages_JSON():

    package_JSON = collection.find({})
    return loads(dumps(package_JSON))