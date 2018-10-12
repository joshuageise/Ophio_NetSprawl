import subprocess
import re
import json
import hostdiscovery
import networkinfo

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

def scanCurrentNetwork():
    interfaces = []
    for func in networkinfo.netFuncs:
        try:
            interfaces = func()
            break
        except:
            continue
    hosts = []
    for interface in interfaces:
        for func in hostdiscovery.scanCIDRFuncs:
            try:
                networkDict = {"network": interface[2]}
                networkHosts = func(interface[2])
                networkDict["hosts"] = networkHosts
                hosts.append(networkDict)
                return json.dumps(hosts)
            except:
                continue
