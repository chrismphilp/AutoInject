import pymongo, re, time, datetime, types

# Parsing related modules
import lxml.html as lh 
import requests

from pymongo        import MongoClient
from json           import loads
from bson.json_util import dumps

from subprocess     import check_output, check_call
from bs4            import BeautifulSoup
from collections    import defaultdict

global ubuntu_version
ubuntu_version = "14"

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
    - Collect the version to be updated to by searching URLs
    - While checking packages, find tells to see if BFS update
    - Once version is retrieved, update the package acordingly (if package cannot be updated, set to non-
    updateable/if update returns error)
4) If packages cannot be updated, set to unupdateable, and remove all matched CVEs, and set new field
to state this package can never be updated
'''

def collect_All_Package_URLs():

    cursor = package_collection.find( {
        'matching_ids' : { '$exists' : True, '$not' : { '$size' : 0 } },
        'updateable' : 1
    } )

    for items in cursor:
        # Call multi-threader function
        pass

def collect_Specific_Package_URL(package_name, cve_id):
    
    cursor = cve_collection.find( { 'id' : cve_id } )

    for urls in cursor['references']: 
        if 'github' in url:
            print("Found github link to BFS:", urls)
            return True

    for urls in cursor['references']:
        version_name = search_URL_For_Version_Update(urls)
        if version_name:
            package_Updater(package_name, version_name)
            return True

    # If none match then do this
    package_collection.update( 
        { 'cve_id' : cve_id },
        { '$set' : { 'cannot_be_updated' : 1 } },
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

def package_Updater(package_name, version_name):
    
    list_Of_Potential_Versions  = []

    madison_versions = check_output(
        ["apt-cache", "madison", package_name],
        universal_newlines=True
    )
    policy_versions = check_output(
        ["apt-cache", "policy", package_name],
        universal_newlines=True
    )
    
    total_output = [x.strip() for x in madison_versions.split("\n")] + [x.strip() for x in policy_versions.split("\n")]
    print(total_output)

    for items in total_output:
        # Update version so that it can be reversed lated if required
        if ("Installed:" in items):
            current = items.split(' ')[1]
            print("Updated previous_version to:", current)
            package_collection.update(
                { 'package_name' : package_name },
                { '$set' : { 'previous_version' : current } },
                multi=True
            )
        # Get the ubuntu version to update to and append to list
        split_substring = items.split(" ")
        for sub_items in split_substring:
            if version_name in sub_items:
                print('Found', version_name, ' in:', sub_items)
                try:
                    if (sub_items not in list_Of_Potential_Versions):   
                        list_Of_Potential_Versions.append(sub_items)
                except:
                    print('Could not add:', items)

    print(list_Of_Potential_Versions)
    
    for versions in list_Of_Potential_Versions:
        combi = package_name + '=' + versions
        try:
            # # package_upgrade = check_call(
            # #     ["sudo", "apt-get", "install", "-y", "--force-yes", "--only-upgrade", combi],
            # #     universal_newlines=True
            # # )
            # if (package_upgrade == 0):
            #     update_Vulnerability_Information(package_name, combi, versions)
            #     return True
            print("Could upgrade with:", combi)
        except:
            print("Couldn't upgrade with:", combi)

def update_Vulnerability_Information(package_name, new_package_version_name, just_version):
    print("Updating vulnerability information")

    # 1) Get all CVE's unmatched from current package and release them
    cursor = package_collection.find( { 'package_name' : package_name } )
    
    for items in cursor['id']:
        cve_collection.update(
            { 'id' : items },
            { '$set' : { 'matched_To_CVE' : 0 } },
            multi=True
        )

    # 2)1) Change new version number accordingly with new_package_version_name
    # 2)2) Also could check whether old version can be downgraded back to?
    
    try:
        re_num                          = re.compile(r"""(?:(\d+\.(?:\d+\.)*\d+))""")
        version                         = re.match(re_num, just_version).group(0)
    except:
        print("Couln't reformat:", just_version)

    formatted_package_name_with_version = package_name + formatted_version
    formatted_version                   = ''.join(e for e in formatted_version if e.isalnum())
    squashed_name_with_version          = package_name + formatted_version        

    try:
        # Update current package data to match updated values 
        package_collection.update(
            { 'package_name' : package_name },
            { '$set' : 
                { 
                    'package_name_with_version' : squashed_name_with_version, #apport2141
                    'formatted_package_name_with_version' :  squashed_name_with_version, #apport2141 
                    'formatted_package_name_without_version' : package_name, #apport
                    'version' : version, #2.1.41
                    'formatted_version' : formatted_version #2141
                } 
            },
            multi=True
        )
        # Push new log data to array
        package_collection.update(
            { 'package_name' : package_name },
            { '$push' : {
                'log' : {
                    'update_type' : 'version',
                    'further' : new_package_version_name,
                    'comment' : 'N/A',
                    'date' : datetime.datetime.now(), 
                    'implementation_type' : 'automatic'
                }
            } },
            multi=False
        )
    except: print("Couldn't update:", package_name)

    # 3) Set the package to no longer be updateable
    package_collection.update(
        { 'package_name' : package_name },
        { '$set' : 
            { 
                'updateable' : 0,
                'has_been_updated' : 1 
            } 
        },
        multi=True
    )

    # 4) Re-search new package version to potentially find new vulnerabilities 

    for package in package_collection.find( { 'package_name' : package_name } ):

        finder_cursor = cve_collection.find(
            { 
                '$text' : { '$search' : items },
                'matched_To_CVE' : 0 
            }
        )

def package_Update_Reversal(package_name):
    print("Reversing package update")
    
    cursor = package_collection.find(
        { 'package_name' : package_name }
    )

    for package in cursor['previous_version']:
        try:
            package_upgrade = check_call(
                ["sudo", "apt-get", "install", "-y", "--force-yes", "--only-upgrade", package]
            )
            if (package_upgrade == 0):
                update_Vulnerability_Information(package_name, combi)
                return True
        except:
            print("Couldn't reverse update:", package_name)

def get_Ubuntu_Version():
    global ubuntu_version

    print("Getting Ubuntu version")
    out = check_output(
        ["lsb_release", "-a"], 
        universal_newlines=True
    )
    tmp = out.split('\n')

    for line in tmp:
        if "Description" in line:
            new_line        = line.split(' ')
            ubuntu_version  = new_line[1]
            if new_line[2]: ubuntu_version += ' ' + new_line[2]
            print(ubuntu_version)

def get_Update_Log(package_name=False):
    if package_name:    
        cursor = package_collection.find({
            'formatted_package_name_with_version' : package_name,
            'log' : { 
                '$exists' : True,
                '$not' : { '$size' : 0 } 
            }
        })
        
        data = { 'log' : [] }
        formatted_data = loads(dumps(cursor))
        for items in formatted_data:
            for logs in items['log']:
                if logs['active'] == 1: data['log'].append(logs)
        cursor = data        
    else:
        cursor = package_collection.find( { 'log' : { '$elemMatch' : { 'active' : 0 } } } )
    return loads(dumps(cursor))
