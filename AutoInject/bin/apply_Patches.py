import pymongo, time, datetime, os

# Parsing related modules
import AutoInject.bin.build_From_Source as bfs
import AutoInject.bin.github_Parser     as gp
import AutoInject.bin.patch_Handler     as ph
import AutoInject.bin.system_Functions  as sf
import AutoInject.bin.website_Parser    as wp

from pymongo                            import MongoClient
from json                               import loads
from bson.json_util                     import dumps
from subprocess                         import check_output, call, PIPE, Popen

client                                  = MongoClient()
package_collection                      = client['package_db']['package_list']
cve_collection                          = client['cvedb']['cves']

def handle_Patch_Update(patch_cursor, package_name):  
    if ('ADMIN' in patch_cursor['id']):
        if (patch_cursor['patch_type'] == 'build_from_source'):
            if (patch_cursor['references']):
                handle_Github_Patch(
                    patch_cursor,
                    package_name, 
                    patch_cursor['references'][0]
                )
            else:
                print("No link provided")
                if not bfs.search_Files(patch_cursor['file_path']): return False
                if determine_File_Status(bfs.search_Files(patch_cursor['file_path'])): return False
                handle_Manual_Patch_By_User(
                    bfs.search_Files(patch_cursor['file_path']),
                    patch_cursor['vulnerable_configuration'][0],
                    patch_cursor['update_code'],
                    patch_cursor['summary'],
                    patch_cursor
                )
            return True
        elif (patch_cursor['patch_type'] == 'version'):
            if not determine_Package_Status(package_name): return False
            if wp.resolve_Admin_Version_Update(patch_cursor, package_name): return True
            else: return False
    elif ('CVE' in patch_cursor['id']):
        print("Standard update")
        for urls in patch_cursor['references']: 
            if 'github' in urls:
                if handle_Github_Patch(
                    patch_cursor,
                    package_name, 
                    url
                ): return True
                else: return False
        print("Collecting URLS")
        if wp.collect_Specific_Package_URL(
            patch_cursor,
            'automatic',
            patch_cursor['summary'],
            False,
            package_name
        ): 
            cve_collection.update_one(
                { 'id' : patch_cursor['id'] },
                { '$set' : { 'deleted' : 1 } }
            )
            return True
        else: 
            cve_collection.update_one(
                { 'id' : patch_cursor['id'] },
                { '$set' : { 
                    'admin_patch_request' : 1,
                    'deleted' : 1 } 
                }
            )
            return False

def handle_Github_Patch(cursor, package_name, url):
    set_to = False
    for (file_path, code) in gp.parse_Github(url):
        if not bfs.search_Files(file_path): return False
        if bfs.perform_Additions(bfs.search_Files(file_path), None, code, False) == False: return False
        if determine_File_Status(file_path): return False

    for (file_path, code) in gp.parse_Github(url): 
        print(file_path, code)
        if not set_to: 
            handle_Manual_Patch_By_User(bfs.search_Files(file_path), package_name, code, 'Github patch: ' + url, cursor)
            set_to = True
        else:
            handle_Manual_Patch_By_User(bfs.search_Files(file_path), package_name, code, 'Github patch: ' + url)
    return True

def handle_Manual_Patch_By_User(full_file_path, package_name, inserted_code, comment, cursor=None):

    if not bfs.perform_File_Alterations(
        full_file_path, 
        bfs.search_Files('AutoInject/file_store/test/patch_file.py'), 
        inserted_code
    ): return False

    diff_file_path = ph.produce_Diff_Of_Files(
        full_file_path,
        bfs.search_Files('AutoInject/file_store/test/patch_file.py'),
        package_name,
        'patch_file__apply__.patch'
    )

    diff_file_path2 = ph.produce_Diff_Of_Files(
        bfs.search_Files('AutoInject/file_store/test/patch_file.py'),
        full_file_path,
        package_name,
        'patch_file__reverse__.patch'
    )

    ph.restore_File_Contents(diff_file_path)
    copy_of_file = ph.make_Copy_Of_File(package_name, full_file_path)

    ph.upload_File(
        package_name,
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
        package_name,
        full_file_path,
        diff_file_path2,
        'build_from_source',
        'manual',
        comment,
        'backward_patch',
        copy_of_file,
        1
    )

    # Compile file is needed
    ph.compile_File(full_file_path)
    if cursor: cve_collection.delete_one( { '_id' : cursor['_id'] } )
    return diff_file_path

def handle_Version_Patch_By_User(package_name, version_name, link, comment):
    
    if not determine_Package_Status(package_name): return False

    if link: return wp.collect_Specific_Package_URL(None, 'manual', comment, link, package_name)
    elif version_name: 
        versions = wp.get_Matching_Ubuntu_Version(package_name, version_name)
        if versions: 
            if wp.perform_Package_Version_Update(versions[0], package_name, versions[1]):
                if wp.update_Vulnerability_Information(
                    package_name,                            
                    sf.get_Ubuntu_Package_Version(package_name),
                    versions[1],
                    'manual',
                    comment
                ): return True
                else: return False

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
        print("OUT", out, len(out))
        if len(out) > 2:    return True
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
