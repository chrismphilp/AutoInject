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

for package_array in listOfPackages:
    print('Package name:', package_array[0])
    print('Version:', package_array[1])
    print('Architecture:', package_array[2])
