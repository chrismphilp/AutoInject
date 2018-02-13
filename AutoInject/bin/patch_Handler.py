import pymongo, re, time, os

from datetime           import datetime
from pymongo            import MongoClient
from subprocess         import check_output, call
from difflib            import unified_diff

client                      = MongoClient()
package_collection          = client['package_db']['package_list']
cve_collection              = client['cvedb']['cves']

def produce_Diff_Of_Files(file_path1, file_path2, package_name, diff_file_name, comment, type_of_patch):    
    
    if (os.path.exists(file_path1) and os.path.exists(file_path2)):
        file_path_of_diff_file = "AutoInject/file_store/" + package_name
        
        if not os.path.exists(file_path_of_diff_file): 
            os.makedirs(file_path_of_diff_file)
        
        full_file_path = file_path_of_diff_file + "/" + diff_file_name
        
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

    # Upload location of file
    upload_File(
        package_name,
        full_file_path,
        'build_from_source',
        'manual',
        comment,
        type_of_patch
    )
    return full_file_path

def upload_File(package_name, file_path, type_Of_Update, type_Of_Implementation, comment, type_of_patch):

    if not os.path.exists('../file_store'):
        os.makedirs('../file_store')

    if not os.path.exists('../file_store/' + package_name):
        os.makedirs('../file_store/' + package_name)

    # copied_file_path    = '../file_store/' + package_name + '/' + filename
    # iteration           = 1

    # while os.path.exists(copied_file_path + str(iteration)):
    #     iteration += 1  
    
    # copyfile(filepath, copied_file_path + str(iteration))

    print("Package name is:", package_name)

    if type_Of_Implementation == 'manual':
        package_collection.update(
            { 'formatted_package_name_with_version' : package_name },
            { '$push' : {
                'log' : { 
                    'file_path' : file_path, 
                    'date' : str(datetime.now()),
                    'update_type' : type_Of_Update,
                    'comment' : comment, 
                    'implementation_type' : type_Of_Implementation,
                    'type_of_patch' : type_of_patch
                }
            } },
            multi=True
        )
    elif type_Of_Implementation == 'automatic':
        package_collection.update(
            { 'package_name' : package_name },
            { '$push' : {
                'log' : { 
                    # 'file_path' : copied_file_path + str(iteration), 
                    # 'datetime' : datetime.datetime.utcnow(),
                    # 'update_type' : type_Of_Implementation,
                    # 'comment' : comment,
                    # 'date' : datetime.datetime.now(), 
                    # 'implementation_type' : type_Of_Update,
                    # 'type_of_patch' : type_of_patch
                }
            } },
            multi=True
        )

def get_Source_Path(path_of_file):
    return os.path.realpath(path_of_file)

def get_Current_Time():
    formatted_time = datetime.utcnow()
    formatted_time = str(formatted_time).split(' ')[1] + ' +0000'
    return formatted_time

def cascase_Patches():
    pass

def restore_File_Contents(path_of_diff):
    os.system("patch -d/ -p0 < " + path_of_diff)
