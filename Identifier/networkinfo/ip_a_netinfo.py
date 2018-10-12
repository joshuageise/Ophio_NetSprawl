import subprocess

"""
This regex looks like complete gibbrish, but when run on the "ip a" command should produce the following output:
Group 1: interface name
Group 2: interface MAC address
Group 3: Interface IP address in CIDR notation
Group 4: Interface Broadcast address

This may return multiple matches, as there are multiple interfaces.
"""
def ip_a_regex():
    return r"\d: (.*):.*\n\s*link.* (.*) brd.*\n\s*inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+) " \
           "(?:brd)? ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"

def ip_a_netinfo():
    output = subprocess.check_output(["ip", "a"]).decode("utf-8")
    pattern = re.compile(ip_a_regex())
    matches = pattern.findall(output)
    toReturn = []
    for match in matches:
        toReturn.append(list(match))
    return toReturn