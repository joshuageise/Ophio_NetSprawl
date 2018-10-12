import subprocess


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