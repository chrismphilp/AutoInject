import pymongo, datetime, os

from shutil import copyfile
from pygments.lexers import guess_lexer_for_filename

from pymongo import MongoClient
from subprocess import check_output

client     	= MongoClient()
db         	= client['package_db']
collection 	= db['package_list']		

def list_files(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))

# list_files(os.path.abspath(os.sep))

def search_Files():
	pass

def upload_File(package_name, filepath, filename, type_Of_Update):

	if not os.path.exists('../file_store'):
		os.makedirs('../file_store')

	if not os.path.exists('../file_store/' + package_name):
		os.makedirs('../file_store/' + package_name)

	copied_file_path 	= '../file_store/' + package_name + '/' + filename
	iteration			= 1

	while os.path.exists(copied_file_path + str(iteration)):
		iteration += 1	
	copyfile(filepath, copied_file_path + str(iteration))

	if type_Of_Update == 'manual_Update':
		collection.update(
			{ 'package_name' : package_name },
			{ '$set' : {
				'manual_Update' : { 
					'file_path' : copied_file_path + str(iteration), 
					'datetime' : datetime.datetime.utcnow()
				}
			} },
			multi=True
		)
	else:
		collection.update(
			{ 'package_name' : package_name },
			{ '$set' : {
				'manual_Update' : { 
					'file_path' : copied_file_path + str(iteration), 
					'datetime' : datetime.datetime.utcnow()
				},
			} },
			multi=True
		)

def language_Checker(filename, text_Of_Language):
	new 	= guess_lexer_for_filename(filename, text_Of_Language)
	print(new)

def restore_File_Contents():
	pass

language_Checker('test.java', 'poo')
# upload_File('python', 'get_Packages.py', 'get_Packages.py', 'manual_Update')
