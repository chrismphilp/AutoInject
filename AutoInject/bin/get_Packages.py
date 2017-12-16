import pymongo, re, time
from json import loads
from bson.json_util import dumps
from pymongo import MongoClient
from subprocess import check_output

client                  = MongoClient()
db                      = client['package_db']
collection              = db['package_list']

package_Names               = []
package_Names_With_Versions = []

def insert_Packages():

    out                 = check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"], 
                            universal_newlines=True)
    tmp                 = out.split('\n')

    # Deleting any current package details
    db.package_list.drop()
    print('Collection names (should be empty):', db.collection_names())
    
    for line in tmp:
        package_array   = line.split('\t')

        try:

            package_Version             = get_Formatted_Version(package_array[1])
            package_Names_With_Version  = get_Formatted_Name(package_array[0]) + ':' + package_Version

            package_item = {
                'package_name_with_version' : package_Names_With_Version,
                'package_name' : package_array[0],
                'version' : package_Version,
                'architecture' : package_array[2]
            }
            package_Names.append(get_Formatted_Name(package_array[0]))
            package_Names_With_Versions.append(package_Names_With_Versions)
        
        except:
            print("Error inserting", package_array)
            continue
        
        result = collection.insert_one(package_item)

    print('Finished inserting into DB')

def get_Formatted_Name(package_Name):

    re_string = re.compile(r"""(([A-Za-z])+(\-[A-Za-z])*)+""")
    return((re.match(re_string, package_Name)).group(0))

def get_Formatted_Version(package_Version):

    re_num = re.compile(r"""([0-9]\.*)+""")
    return((re.match(re_num, package_Version)).group(0)) 

def get_Packages_JSON():

    package_JSON = collection.find({})
    return loads(dumps(package_JSON))