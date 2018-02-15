import pymongo, re, time, os

from datetime           import datetime
from pymongo            import MongoClient
from subprocess         import check_output, call
from difflib            import unified_diff
from shutil             import copyfile

from json               import loads
from bson.json_util     import dumps

client                      = MongoClient()
package_collection          = client['package_db']['package_list']
cve_collection              = client['cvedb']['cves']

def produce_Diff_Of_Files(file_path1, file_path2, package_name, diff_file_name):    

    if not os.path.exists('../file_store'):
        os.makedirs('../file_store')

    if not os.path.exists('../file_store/' + package_name):
        os.makedirs('../file_store/' + package_name)

    if (os.path.exists(file_path1) and os.path.exists(file_path2)):
        file_path_of_diff_file = "AutoInject/file_store/" + package_name
        
        if not os.path.exists(file_path_of_diff_file): 
            os.makedirs(file_path_of_diff_file)
        
        full_file_path = file_path_of_diff_file + "/" + diff_file_name

        iteration = 1
        while (os.path.exists(full_file_path)):
            iteration += 1
            full_file_path = file_path_of_diff_file + "/" + str(iteration) + diff_file_name
        
        with open(full_file_path, "w") as outfile:
            
            line_no = 0
            file1   = open(file_path1, "r")
            file2   = open(file_path2, "r")

            for lines in unified_diff(file1.readlines(), file2.readlines()):
                print(lines)
                if (line_no == 0):
                    line_no += 1
                    new_string = "--- " + get_Source_Path(file_path1) + " " + get_Current_Time() + '\n'
                    outfile.write(new_string)
                elif (line_no == 1):
                    line_no += 1
                    new_string = "+++ " + get_Source_Path(file_path2) + " " + get_Current_Time() + '\n'
                    outfile.write(new_string)
                else:   
                    outfile.write(lines)
    else:
        print("Path to files does not exist")
    
    return full_file_path

def upload_File(package_name, original_files_path, diff_file_path, type_of_update, type_of_implementation, comment, 
    type_of_patch, copy_of_file_path, active):

    print("Package name is:", package_name)

    package_collection.update(
        { 'formatted_package_name_with_version' : package_name },
        { '$push' : {
            'log' : { 
                'original_files_path' : original_files_path,
                'file_path_of_diff' : diff_file_path, 
                'date' : str(datetime.now()),
                'update_type' : type_of_update,
                'comment' : comment, 
                'implementation_type' : type_of_implementation,
                'type_of_patch' : type_of_patch, # forward / backward
                'file_path_of_copy' : copy_of_file_path,
                'active' : active, # 1 -> active, 0 -> not active
                'path_of_intermediate_store' : 'N/A'
            }
        } },
        multi=True
    )

def handle_Patch_Maintenance(date_of_patch, package):
    reverser = package_collection.find_one( 
        { 'log' : 
            { '$elemMatch' :  { 
                'date' : date_of_patch,
                'active' : 1 
            } } 
        } 
    )
    print("Reverser:", reverser)
    if reverser:
        formatted_data = loads(dumps(reverser))
        for elements in formatted_data['log']:
            if elements['date'] == date_of_patch:
                if (elements['type_of_patch'] == 'backward_patch'): 
                    apply_Reversal(elements, package)
                elif (elements['type_of_patch'] == 'forward_patch'):
                    apply_Forward(elements)
    else: print("No file matching")

def apply_Reversal(json_of_patch, package):

    if (json_of_patch['path_of_intermediate_store'] == 'N/A'):
        copy_name = make_Copy_Of_File(package, json_of_patch['original_files_path'])
    else:
        copy_name = make_Copy_Of_File("--", json_of_patch['original_files_path'], json_of_patch['path_of_intermediate_store'])

    # Update the reversal patch
    package_collection.update_one(
        {   'log' : 
            { '$elemMatch' : 
                {   'file_path_of_copy' : json_of_patch['file_path_of_copy'],
                    'active' : 1,
                    'type_of_patch' : 'backward_patch' } 
            } 
        },
        { '$set' : { 'log.$.path_of_intermediate_store' : copy_name, 'log.$.active' : 0 } }
    )
    # Update the forward patch
    package_collection.update_one(
        {   'log' : 
            { '$elemMatch' : 
                {   'file_path_of_copy' : json_of_patch['file_path_of_copy'],
                    'active' : 0,
                    'type_of_patch' : 'forward_patch' } 
            } 
        },
        { '$set' : { 'log.$.path_of_intermediate_store' : copy_name, 'log.$.active' : 1 } }
    )

    with open(json_of_patch['file_path_of_copy'], 'r') as file_to_read:
        content_of_file = file_to_read.read()
        with open(json_of_patch['original_files_path'], 'w') as file_to_write:
            file_to_write.write(content_of_file)

    restore_File_Contents(json_of_patch['file_path_of_diff'])

def apply_Forward(json_of_patch):

    with open(json_of_patch['path_of_intermediate_store'], 'r') as file_to_read:
        content_of_file = file_to_read.read()
        with open(json_of_patch['original_files_path'], 'w') as file_to_write:
            file_to_write.write(content_of_file)

    # Update the reversal patch
    package_collection.update_one(
        {   'log' : 
            { '$elemMatch' : 
                {   'file_path_of_copy' : json_of_patch['file_path_of_copy'],
                    'active' : 1,
                    'type_of_patch' : 'forward_patch' } 
            } 
        },
        { '$set' : { 'log.$.active' : 0 } }
    )
    # Update the forward patch
    package_collection.update_one(
        {   'log' : 
            { '$elemMatch' : 
                {   'file_path_of_copy' : json_of_patch['file_path_of_copy'],
                    'active' : 0,
                    'type_of_patch' : 'backward_patch' } 
            } 
        },
        { '$set' : { 'log.$.active' : 1 } }
    )

def make_Copy_Of_File(package_name, file_path, set_Path=False):

    if set_Path:
        copyfile(file_path, set_Path)
        return set_Path
    else:
        copy = "AutoInject/file_store/" + package_name + "/copy"
        count = 0
        while (os.path.exists(copy)):
            count += 1
            copy = "AutoInject/file_store/" + package_name + "/copy" + str(count)
        copyfile(file_path, copy)
        return get_Source_Path(copy)

def restore_File_Contents(path_of_diff):
    os.system("patch --force -d/ -p0 < " + path_of_diff)

def get_Source_Path(path_of_file):
    return os.path.realpath(path_of_file)

def get_Current_Time():
    formatted_time = datetime.utcnow()
    formatted_time = str(formatted_time).split(' ')[1] + ' +0000'
    return formatted_time
