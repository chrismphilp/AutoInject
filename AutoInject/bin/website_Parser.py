import pymongo, re, time, datetime, types, requests

from    AutoInject.bin.database_Handler     import Database
import  AutoInject.bin.system_Functions     as sf

# Parsing related modules
import lxml.html    as lh 

from pymongo        import MongoClient
from json           import loads
from bson.json_util import dumps
from subprocess     import check_output, check_call
from bs4            import BeautifulSoup
from collections    import defaultdict

client                      = MongoClient()
package_collection          = client['package_db']['package_list']
cve_collection              = client['cvedb']['cves']

db                          = Database()

kwargs  = {
    'bugzilla.redhat' : { 
        'finder' : re.compile(r""".*bugzilla.redhat.*"""), 
        'search_info' : '//td[@id="field_container_cf_fixed_in"]/text()',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""") 
    },
    'ubuntu' : {
        'finder' : re.compile(r""".*ubuntu\.com.*"""),
        'search_info' : '//dl/dt[text()="Ubuntu 14.04 LTS"]/following::dd[1]/a/text()',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""")
    },
    'launchpad_trunk' : {
        'finder' : re.compile(r""".*launchpad\.net.*trunk.*"""),
        'search_info' : '//div[@class="yui-t4"]/div[@id="maincontent"]/div/div/h1/text()',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""")
    },
    'launchpad' : {
        'finder' : re.compile(r""".*launchpad\.net.*"""),
        'search_info' : '//dd[@id="yui_3_10_3_1_1516828240604_66"]/text()',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""")
    },
    'exchange' : {
        'finder' : re.compile(r""".*exchange\.xforce.*"""),
        'search_info' : '//p[@class="detailsline description"]/p/text()',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""")
    }
}
list_Of_Parsing_Procedures = defaultdict(dict, **kwargs)

def collect_All_Package_URLs():

    cursor = package_collection.find( {
        'matching_ids' : { '$exists' : True, '$not' : { '$size' : 0 } },
        'updateable' : 1
    } )

    for packages in cursor:
        # Call multi-threader function
        pass

def resolve_Admin_Version_Update(cursor, package_name):

    if not sf.connected_To_Internet(): return False

    if cursor['references']:
        if collect_Specific_Package_URL(
            cursor,
            'manual',
            cursor['summary'],
            False, 
            package_name
        ):
            cve_collection.delete_one( { '_id' : cursor['_id'] } )
            return True
    elif cursor['version_number']:
        versions = get_Matching_Ubuntu_Version(cursor['individual_package_name'], cursor['version_number'])
        if versions: 
            if perform_Package_Version_Update(versions[0], cursor['individual_package_name'], versions[1]):
                if update_Vulnerability_Information(
                    cursor['individual_package_name'],                            
                    sf.get_Ubuntu_Package_Version(cursor['individual_package_name']),
                    versions[1],
                    'manual',
                    cursor['summary']
                ): 
                    cve_collection.delete_one( { '_id' : cursor['_id'] } )
                    return True
        return False

def collect_Specific_Package_URL(cursor, implementation_type='automatic', comment=False, link=False, package_name=False,
    unformatted_package_name=False):
    
    if not sf.connected_To_Internet(): return False

    if link:
        version_name = search_URL_For_Version_Update(link)
        if version_name:
            versions = get_Matching_Ubuntu_Version(package_name, version_name)
            if versions: 
                if perform_Package_Version_Update(versions[0], package_name, versions[1]):
                    if update_Vulnerability_Information(
                        package_name,                            
                        sf.get_Ubuntu_Package_Version(package_name),
                        versions[1],
                        implementation_type,
                        comment
                    ): return True
                    else: return False
            else: return False
    elif cursor:        
        for urls in cursor['references']:
            version_name = search_URL_For_Version_Update(urls)
            if version_name:
                print(version_name)
                version_list = get_Matching_Ubuntu_Version(package_name, version_name)   
                if version_list: 
                    if perform_Package_Version_Update(version_list[0], package_name, version_list[1]):
                        if update_Vulnerability_Information(
                            package_name,                            
                            sf.get_Ubuntu_Package_Version(package_name),
                            version_list[1],
                            implementation_type,
                            comment
                        ): return True
                        else: return False
                else: return False
    else: return False

def search_URL_For_Version_Update(url):
    print('Scanning:', url)
    start       = time.time()
    matched     = False

    for key, value in list_Of_Parsing_Procedures.items():
        
        if matched: 
            end = time.time()
            print('Total time for match:', end - start)
            return version_name

        if (re.match(value['finder'], url)):
            print('Matched with:', value['finder'])
            try:
                req_time        = time.time()
                page            = requests.get(url)
                print('Total request time:', time.time() - req_time)
                tree            = lh.fromstring(page.content)
                update_name     = tree.xpath(value['search_info'])
                print("Searching website and found:", update_name)
                
                if update_name: 
                    for items in update_name:   
                        version_name = re.findall(value['compiler'], items)
                        if (version_name): 
                            if type(version_name) is list:
                                version_name = version_name[0]
                            print("Found a match!:", version_name)                            
                            matched = True 
            except:
                print("Couldn't match:", url)
    
    end = time.time()
    print('Total time for requests:', end - start)

    if matched: return version_name
    else:       return False 

def get_Matching_Ubuntu_Version(package_name, version_name):
    
    list_of_potential_versions  = []
    version_name                = ''.join(e for e in version_name if e.isalnum())
    previous_version            = package_collection.find_one( { 'package_name' : package_name } )['ubuntu_version']

    madison_versions = check_output(
        ["apt-cache", "madison", package_name],
        universal_newlines=True
    )
    policy_versions = check_output(
        ["apt-cache", "policy", package_name],
        universal_newlines=True
    )
    
    total_output = [x.strip() for x in madison_versions.split("\n")] + [x.strip() for x in policy_versions.split("\n")]

    for items in total_output:
        # Get the ubuntu version to update to and append to list
        for sub_items in items.split(" "):
            if (version_name in ''.join(e for e in sub_items if e.isalnum())):
                print("Sub items:", sub_items)
                print("Current version:", previous_version)
                if (sub_items != previous_version and (package_name + "=" + sub_items) not in list_of_potential_versions): 
                    print('Found', version_name, ' in:', sub_items)
                    list_of_potential_versions.append(package_name + "=" + sub_items)

    if list_of_potential_versions: 
        print("List of potential versions:", list_of_potential_versions)
        return (list_of_potential_versions, previous_version)
    else: return False

def perform_Package_Version_Update(list_of_potential_versions, package_name, previous_version, full_version=False):
    if full_version:
        full_package_install_name = package_name + "=" + full_version
        print("Install name:", full_package_install_name)
        try:
            package_upgrade = check_call(
                ["sudo", "apt-get", "install", "-y", "--force-yes", full_package_install_name],
                universal_newlines=True
            )
            if ((package_name + "=" + sf.get_Ubuntu_Package_Version(package_name)) == full_package_install_name):
                return full_package_install_name
            else: 
                print("Not upgraded with:", full_package_install_name)
                return False
        except: print("Could not upgrade with:", full_version); return False
    else:
        for version in list_of_potential_versions:
            try:
                package_upgrade = check_call(
                    ["sudo", "apt-get", "install", "-y", "--force-yes", version],
                    universal_newlines=True
                )
                if ((package_name + "=" + sf.get_Ubuntu_Package_Version(package_name)) != previous_version):
                    print("Upgraded from:", previous_version, "to:", version)
                    return (package_name, version, previous_version)
                else: 
                    print("Not upgraded with:", version)
                    return False
            except: print("Could not upgrade with:", version); return False

def update_Vulnerability_Information(package_name, current_version, previous_version, implementation_type, comment=False):

    print("Updating vulnerability information")

    # 1) Get all CVE's unmatched from current package and release them
    cursor = package_collection.find_one( { 'package_name' : package_name } )
    
    for items in cursor['matching_ids']:
        cve_collection.update_one(
            { 'id' : items },
            { '$set' : { 
                'matched_To_CVE' : 0,
                'matched_to' : 0 
            } }
        )

    # 2)1) Change new version number accordingly with new_package_version_name
    # 2)2) Also could check whether old version can be downgraded back to?

    # Push new log data to array
    if not comment: comment = ('From:' + previous_version + 'To:' + current_version)

    shared_log_id = db.get_Incremented_Id()

    package_collection.update_one(
        { 'package_name' : package_name },
        { '$push' : {
            'log' : {
                '$each' : [ {
                        'update_type' : 'version',
                        'comment' : comment,
                        'date' : str(datetime.datetime.now()), 
                        'implementation_type' : implementation_type,
                        'active' : 1,
                        'type_of_patch' : 'backward_patch',
                        'original_files_path' : previous_version,
                        'file_path_of_diff' : 'N/A',
                        'linking_id' : shared_log_id
                    },
                    {
                        'update_type' : 'version',
                        'comment' : comment,
                        'date' : str(datetime.datetime.now()), 
                        'implementation_type' : implementation_type,
                        'active' : 0,
                        'type_of_patch' : 'forward_patch',
                        'original_files_path' : current_version,
                        'file_path_of_diff' : 'N/A',
                        'linking_id' : shared_log_id
                    }
                ]
            }
        },
        '$set' : { 'matching_ids' : [] } }
    )
    return True

if __name__ == '__main__':
    # print(get_Matching_Ubuntu_Version('golang', '2.1.2'))
    print(search_URL_For_Version_Update('https://usn.ubuntu.com/3480-1/'))
    # print(search_URL_For_Version_Update('https://usn.ubuntu.com/2353-1/'))
    # CVE-2017-14810 - ID for demo