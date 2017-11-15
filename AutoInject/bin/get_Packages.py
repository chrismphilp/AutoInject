import pymongo
from pymongo import MongoClient
from subprocess import check_output

client          = MongoClient()
db              = client['package_db']
collection      = db['package_list']

out             = check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"])
tmp             = out.split('\n')
listOfPackages  = []

for line in tmp:
    ntmp        = line.split('\t')
    listOfPackages.append(ntmp)

db.package_list.delete_many({})
print('Collection names:', db.collection_names())

python_data = collection.find_one({ 'package_name' : 'python' })
print(python_data)

for package_array in listOfPackages:
    
    try:
        package_item = {
            'package_name' : package_array[0],
            'version' : package_array[1],
            'architecture' : package_array[2]
        }
    
    except:
        print("Error inserting", package_array)
        continue
    
    result = collection.insert_one(package_item)

print('Finished inserting into DB')

python_data = collection.find_one({ 'package_name' : 'python' })
print(python_data)
