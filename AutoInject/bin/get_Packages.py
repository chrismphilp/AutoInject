from subprocess import check_output
import shlex

out = check_output(["dpkg-query", "-W", "-f", "=",
                    "${binary:Package}\n"])

print(out)