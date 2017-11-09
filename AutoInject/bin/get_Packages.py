from subprocess import check_output

out = check_output(["dpkg-query", "-l"])
print(out)