import pymongo, re, time, datetime, types, requests

import AutoInject.bin.system_Functions as sf
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

kwargs  = {
    'bugzilla.redhat' : { 
        'finder' : re.compile(r""".*bugzilla.redhat.*"""), 
        'search_info' : '//td[@id="field_container_cf_fixed_in"]/text()',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""") 
    },
    'securityfocus' : {
        'finder' : re.compile(r""".*securityfocus.*"""),
        'search_info' : '',
        'compiler' : re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""")
    },
    'ubuntu' : {
        'finder' : re.compile(r""".*ubuntu\.com.*"""),
        'search_info' : '//dl/dd/span/a/text()',
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

'''
1) Collect list of references for package, in order of severity
2) Place each package into a multi-threaded queue 
3) For each package CVE:
    - Check packages, find tells to see if BFS update
    - Collect the version to be updated to by searching URLs
    - Once version is retrieved, update the package acordingly (if package cannot be updated, 
    set CVE to non-updateable/if update returns error)
4) If packages cannot be updated, set to unupdateable, and remove all matched CVEs, and set new field
to state this package can never be updated
'''

def collect_All_Package_URLs():

    cursor = package_collection.find( {
        'matching_ids' : { '$exists' : True, '$not' : { '$size' : 0 } },
        'updateable' : 1
    } )

    for packages in cursor:
        # Call multi-threader function
        pass

def resolve_Admin_Version_Update(cursor):

    if not sf.connected_To_Internet(): return False

    if cursor['references']:
        collect_Specific_Package_URL(cursor)
    elif cursor['version_number']:
        get_Matching_Ubuntu_Version(cursor['package_name'], cursor['version_number'])

def collect_Specific_Package_URL(cursor, link=False):
    
    if not sf.connected_To_Internet(): return False

    if link:
        version_name = search_URL_For_Version_Update(link)
        if version_name:
            print(version_name)
            if get_Matching_Ubuntu_Version(package_name, version_name): return True
            else: return False
    else:        
        for urls in cursor['references']:
            version_name = search_URL_For_Version_Update(urls)
            if version_name:
                print(version_name)
                if get_Matching_Ubuntu_Version(package_name, version_name): return True
                else: return False

        # If none match then do this
        cve_collection.update( 
            { '_id' : cursor['_id'] },
            { '$set' : { 'deleted' : 1 } },
            multi=True
        )
        return False

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
                
                if (update_name): 
                    for items in update_name:   
                        version_name = re.findall(value['compiler'], items)
                        if (version_name): 
                            print("Found a match!:", version_name)
                            if type(version_name) is list:
                                version_name = version_name[0]
                            matched = True 
            except:
                print("Couldn't match:", url)
    
    end = time.time()
    print('Total time for requests:', end - start)

    if matched: return version_name
    else:       return False 

def get_Matching_Ubuntu_Version(package_name, version_name):
    
    list_Of_Potential_Versions  = []
    version_name                = ''.join(e for e in version_name if e.isalnum())
    current_version             = package_collection.find_one( { 'package_name' : package_name } )['current_ubuntu_version']

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
                print("Current version:", current_version)
                if (sub_items != current_version and (package_name + "=" + sub_items) not in list_Of_Potential_Versions): 
                    print('Found', version_name, ' in:', sub_items)
                    list_Of_Potential_Versions.append(package_name + "=" + sub_items)

    if list_Of_Potential_Versions: 
        print("List of potential versions:", list_Of_Potential_Versions)
        perform_Package_Version_Update(list_Of_Potential_Versions, package_name, current_version)
    else: return False

def perform_Package_Version_Update(list_Of_Potential_Versions, package_name, previous_version):
    for version in list_Of_Potential_Versions:
        try:
            package_upgrade = check_call(
                ["sudo", "apt-get", "install", "-y", "--force-yes", version],
                universal_newlines=True
            )
            if ((package_name + "=" + sf.get_Ubuntu_Package_Version(package_name)) != previous_version):
                print("Upgraded from:", previous_version, "to:", version)
                # return update_Vulnerability_Information(package_name, version, previous_version)
            else: 
                print("Not upgraded with:", version)
                return False
        except: print("Could not upgrade with:", version); return False

def update_Vulnerability_Information(package_name, current_version, previous_version, implementation_type, comment=False):
    print("Updating vulnerability information")

    # 1) Get all CVE's unmatched from current package and release them
    cursor = package_collection.find( { 'package_name' : package_name } )
    
    for items in cursor['id']:
        cve_collection.update(
            { 'id' : items },
            { '$set' : { 
                'matched_To_CVE' : 0,
                'matched_to' : 0 
            } }
        )

    # 2)1) Change new version number accordingly with new_package_version_name
    # 2)2) Also could check whether old version can be downgraded back to?

    try:
        package_version                         = sf.get_Formatted_Version(version)
        formatted_package_name_without_version  = sf.get_Formatted_Name(package_name)
        squashed_version                        = ''.join(e for e in package_version if e.isalnum())
        package_name_with_version               = formatted_package_name_without_version + squashed_version
        squashed_name_with_version              = ''.join(e for e in package_name_with_version if e.isalnum() or e == ':')
    except: print("Couln't reformat:", version); return False

    # Update current package data to match updated values 
    package_collection.update(
        { 'package_name' : package_name },
        { '$set' : { 
            'package_name_with_version' : package_name_with_version, #apport2141
            'formatted_package_name_with_version' :  squashed_name_with_version, #apport2141 
            'formatted_package_name_without_version' : package_name, #apport
            'version' : package_version, #2.1.41
            'formatted_version' : formatted_version #2141
        } }
    )
    # Push new log data to array
    if not comment: comment = ('From:' + previous_version + 'To:' + current_version)

    shared_log_id = sf.get_Incremented_Id()

    package_collection.update(
        { 'package_name' : package_name },
        { '$push' : {
            'log' : {
                '$each' : [ {
                        'update_type' : 'version',
                        'comment' : comment,
                        'date' : str(datetime.datetime.now()), 
                        'implementation_type' : implementation_type,
                        'active' : 1,
                        'type_of_patch' : 'forward',
                        'original_files_path' : package_name,
                        'file_path_of_diff' : 'N/A',
                        'linking_id' : shared_log_id
                    },
                    {
                        'update_type' : 'version',
                        'comment' : comment,
                        'date' : str(datetime.datetime.now()), 
                        'implementation_type' : implementation_type,
                        'active' : 0,
                        'type_of_patch' : 'backward',
                        'original_files_path' : package_name,
                        'file_path_of_diff' : 'N/A',
                        'linking_id' : shared_log_id
                    }
                ]
            }
        } }
    )

def package_Update_Reversal(package_name):
    print("Reversing package update")
    
    cursor = package_collection.find_one( { 'package_name' : package_name } )

    for package in cursor['previous_version']:
        try:
            package_upgrade = check_call(
                ["sudo", "apt-get", "install", "-y", "--force-yes", package]
            )
            if (package_upgrade == 0):
                update_Vulnerability_Information(package_name, combi)
                return True
        except:
            print("Couldn't reverse update:", package_name)

if __name__ == '__main__':
    print(get_Matching_Ubuntu_Version('golang', '2.1.2'))
