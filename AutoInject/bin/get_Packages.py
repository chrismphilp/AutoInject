from subprocess import check_output
import shlex

out             = check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"])
tmp             = out.split('\n')
listOfPackages  = []
for line in tmp:
    ntmp = line.split('\t')
    listOfPackages.append(ntmp)
print(listOfPackages)