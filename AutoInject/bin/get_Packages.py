import  pymongo, re, time
import  AutoInject.bin.system_Functions as sf

from    pymongo                         import MongoClient
from    subprocess                      import check_output

client           = MongoClient()
collection       = client['package_db']['package_list']

def get_Package_Data():
    
    tmp = check_output(
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t{binary:Summary}\n"], 
        universal_newlines=True
    ).split('\n')
    
    list_to_insert              = []
    package_names_with_versions = []
    ubuntu_versions             = []

    for line in tmp:
        
        package_array = line.split('\t')

        # try:
        package_version                         = sf.get_Formatted_Version(package_array[1])
        squashed_version                        = ''.join(e for e in package_version if e.isalnum())
        package_name_with_version               = formatted_package_name_without_version + squashed_version
        squashed_name_with_version              = ''.join(e for e in package_name_with_version if e.isalnum() or e == ':')

        package_item = {
            'package_name' : package_array[0],   
            'formatted_package_name_with_version' : squashed_name_with_version,                
            'architecture' : package_array[2],
            'summary' : package_array[3],
            # 1 = updateable, 0 means do not update
            'updateable' : 1,
            'ubuntu_version' : package_array[1],
            'apt_version' : package_array[0] + '=' + package_array[1],
            'matching_ids' : []
        }
        list_to_insert.append(package_item)
        package_names_with_versions.append(squashed_name_with_version)
        ubuntu_versions.append(package_array[0] + '=' + package_array[1])
        # except:
        #     print("Error inserting", package_array)
        #     continue
    return (list_to_insert, package_names_with_versions, ubuntu_versions)
