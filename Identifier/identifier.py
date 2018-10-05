import subprocess
import re
import json

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

"""
scanNetwork takes three parameters, the first is the ip address of the network or a host on the network
the second, is the subnet mask in CIDR notation. An example IP: 192.168.1.0     An example subnet: 24

The third parameter is a speed parameter, on a scale of 0-5. 5 is probably a bad idea.

returns an array of ip addresses as strings
"""
def scanNetworkNMAP(ipAddress:str, subnet:str, speed:str="3"):
    output = subprocess.check_output(["nmap", "-T{}".format(speed), "-sn", "{}/{}".format(ipAddress, subnet)]).decode("utf-8")
    ipAddresses = []
    for line in output.split("\n"):
        if "Nmap scan report" in line:
            ipAddresses.append(line.split(" ")[-1])

    return ipAddresses

def scanNetworkNMAPCIDR(cidrAddress:str, speed:str="3"):
    split = cidrAddress.split("/")
    return scanNetworkNMAP(split[0], split[1], speed)

"""
Stub function for now, could be a long-form version of scanNetworkNMAP
"""
def scanNetwork(ipAddress:str, subnet:str, speed:str):
    scanNetworkNMAP(ipAddress, subnet, speed)

"""
getNetwork information takes no parameters

returns a list of lists specified in ip_a_regex
"""
def getNetworkInformation():
    output = subprocess.check_output(["ip", "a"]).decode("utf-8")
    pattern = re.compile(ip_a_regex())
    matches = pattern.findall(output)
    toReturn = []
    for match in matches:
        toReturn.append(list(match))
    return toReturn

def scanCurrentNetwork():
    netInfo = getNetworkInformation()
    hosts = []
    for network in netInfo:
        networkDict = {"network": network[2]}
        networkHosts = scanNetworkNMAPCIDR(network[2])
        networkDict["hosts"] = networkHosts
        hosts.append(networkDict)
    return json.dumps(hosts)



#scanNetwork("192.168.1.0", "24")
#getNetworkInformation()
print(scanCurrentNetwork())
