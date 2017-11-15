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
print(db.collection_names())


for package_array in listOfPackages:
    
    # print('Package name:', package_array[0])
    # print('Version:', package_array[1])
    # print('Architecture:', package_array[2])
    # print()
    
    try:
        package_item = {
            'package_name' : package_array[0],
            'version' : package_array[1],
            'architecture' : package_array[2]
        }
    
    except:
        continue
    
    result = collection.insert_one(package_item)
    # print('Result ID', result.inserted_id)

print('Finished inserting into DB')

python_data = collection.find_one({ 'package_name' : 'python' })
print(python_data)
