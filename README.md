# AutoInject

A software for automatically patching vulnerabilities.

### Prerequisites

* Ubuntu Trusty 14.04
* CVE-Search
* Mongo 3.2
* Python - 3.3 or above

## Sudo Permissions

Must give sudo permissions for all files in the folder.
```
AutoInject/bin/sudo_scripts/ 
```
See this guide for further details on how to provide sudo permissions:

## Running the package

Firstly, remove these lines from */cve-search/sbin/db_updater.py*

```
{'name': "cpe", 'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_dictionary.py")},
{'name': "cpeother", 'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_other_dictionary.py")}
```     

Secondly, you must provide *sudo* permissions for the AutoInject directory, as it will need to make file and folder changes.

Once done, the file_structure of the system must be ensured to be correct, with the base folder set to AutoInject, containing all 
of the system files. Alongside this directory the CVE-search folder must be placed so the eventual file layout is as follows.

```
/AutoInject
	/AutoInject
	auto_inject_script
	other files
/CVE-Search 
```

Then, either run these commands:
```
export FLASK_APP=AutoInject
export FLASK_DEBUG=true
sudo pip3 install -e .
flask run
```

Or use the provided script: 

```
auto_inject_script
```

These commands MUST BE RUN from the inner

```
/AutoInject
```

folder.

Once the application has launched, navigate to the documentation page located under the
About heading for further information regarding the use of the application.
