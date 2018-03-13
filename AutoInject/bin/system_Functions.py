import pymongo, re

from time               import time
from pymongo            import MongoClient
from subprocess         import check_output

try:                    import httplib
except:                 import http.client as httplib

def connected_To_Internet():
    start = time()
    conn = httplib.HTTPConnection("www.google.com", timeout=5)
    try:
        conn.request("/HEAD", "/")
        conn.close()
        print("Connection request completed in:", time() - start)
        return True
    except:
        conn.close()
        print("Connection request completed in:", time() - start)
        return False

def get_Ubuntu_Package_Version(package_name):
    try:
        apt_get_version = check_output(
            ["dpkg-query", "-W", "-f=${Version}\n", package_name], 
            universal_newlines=True
        ).split('\n')
        if apt_get_version: return apt_get_version[0]
        else: return "(none)"
    except: return "(none)"

def get_Formatted_Name(package_Name):
    re_string = re.compile(r"""([0-9]{0,1}([A-Za-z])+(\-[A-Za-z])*)+""")
    return (re.match(re_string, package_Name)).group(0)

def get_Formatted_Version(package_Version):
    re_num = re.compile(r"""(([0-9]:){0,1}[0-9]\.*)+""")
    return (re.match(re_num, package_Version)).group(0)

def run_Database_Updater_Script():
    print("Running script")
    subprocess.call(["python3", "../cve-search/sbin/db_updater.py", "-v"])
