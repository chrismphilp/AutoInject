import pymongo, time, datetime, os

# Parsing related modules
import AutoInject.bin.build_From_Source as bfs
import AutoInject.bin.github_Parser     as gp
import AutoInject.bin.patch_Handler     as ph

from pymongo                            import MongoClient
from json                               import loads
from bson.json_util                     import dumps
from subprocess                         import check_output, call, PIPE, Popen

client                                  = MongoClient()
package_collection                      = client['package_db']['package_list']
cve_collection                          = client['cvedb']['cves']

def handle_Admin_Patch(patch_cursor):
    if (patch_cursor['patch_type'] == 'build_from_source'):
        if (patch_cursor['references']): 
            handle_Github_Patch(patch_cursor['references'])
        else:
            print("No link provided")
            handle_Manual_Patch_By_User(
                bfs.search_Files(patch_cursor['file_path']),
                patch_cursor['vulnerable_configuration'][0],
                patch_cursor['update_code'],
                patch_cursor['summary'],
                patch_cursor
            )
    elif (patch_cursor['patch_type'] == 'version'):
        if (patch_cursor['references']):
            print("Link provided")
        else:
            print("No link provided")

def handle_Github_Patch(package, url):
    list_of_updates = []
    for (file_path, code) in gp.parse_Github(url): 
        handle_Manual_Patch_By_User(bfs.search_Files(url), package, code, 'Github patch: ' + url)

def handle_Manual_Patch_By_User(full_file_path, package, inserted_code, comment, cursor=None):

    bfs.perform_File_Alterations(
        full_file_path, 
        'AutoInject/file_store/test/patch_file.py', 
        inserted_code
    )

    diff_file_path = ph.produce_Diff_Of_Files(
        full_file_path,
        'AutoInject/file_store/test/patch_file.py',
        package,
        'patch_file__apply__.patch'
    )

    diff_file_path2 = ph.produce_Diff_Of_Files(
        'AutoInject/file_store/test/patch_file.py',
        full_file_path,
        package,
        'patch_file__reverse__.patch'
    )

    ph.restore_File_Contents(diff_file_path)
    copy_of_file = ph.make_Copy_Of_File(package, full_file_path)

    ph.upload_File(
        package,
        full_file_path,
        diff_file_path,
        'build_from_source',
        'manual',
        comment,
        'forward_patch',
        copy_of_file,
        0
    )

    ph.upload_File(
        package,
        full_file_path,
        diff_file_path2,
        'build_from_source',
        'manual',
        comment,
        'backward_patch',
        copy_of_file,
        1
    )

    if cursor: cve_collection.delete_one( { '_id' : cursor['_id'] } )

    return diff_file_path

def determine_File_Status(file_path):
    try:
        p1 = Popen(
            ["lsof", "-l"],
            stdout=PIPE
        )
        p2 = Popen(
            ["grep", ph.get_Source_Path(file_path)],
            stdin=p1.stdout,
            stdout=PIPE
        )
        p1.stdout.close()
        out, err = output = p2.communicate()
        
        if (len(out) > 2):  return True
        else:               return False
    except:
        return False

def determine_Package_Status(package_name):
    try:
        p1 = Popen(
            ["dpkg", "-L", package_name],
            stdout=PIPE
        )
        p2 = Popen(
            ["grep", package_name],
            stdin=p1.stdout,
            stdout=PIPE
        )
        p1.stdout.close()
        out, err = output = p2.communicate()

        count = 0
        for file_in_package in str(out).split("\\n"):
            if count > 5:
                p3 = Popen(
                    ["lsof", "-l"],
                    stdout=PIPE
                )
                p4 = Popen(
                    ["grep", file_in_package],
                    stdin=p3.stdout,
                    stdout=PIPE
                )
                p3.stdout.close()
                out, err = output = p4.communicate()
            
            if (len(out) > 2):  return True
            elif (count > 10):  return False
            else:               count += 1
    except:
        return False
