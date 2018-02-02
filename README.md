# AutoInject

A software for automatically patching vulnerabilities.

### Prerequisites

* Python - 3.3 or above
* Flask-PyMongo

## Sudo Permissions

Must give sudo permissions for all files in the folder.
```
AutoInject/bin/sudo_scripts/ 
```

## Running the package

```
export FLASK_APP=AutoInject
export FLASK_DEBUG=true
sudo pip3 install -e .
flask run
```
