from subprocess import check_output
import shlex

out = check_output(["dpkg-query", "-W", 
    "-f=${binary:Package}\n{binary:Package}\t${Version}\t${Architecture}\n"])

print(out)