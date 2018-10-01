import ipaddress
import subprocess
import socket

"""
scanNetwork takes two parameters, the first is the ip address of the network or a host on the network
the second, is the subnet mask in CIDR notation. An example IP: 192.168.1.0     An example subnet: 24

returns an array of ip addresses as strings
"""
def scanNetwork(ipAddress, subnet):
    output = subprocess.check_output(["nmap", "-sn", "{}/{}".format(ipAddress, subnet)]).decode("utf-8")
    ipAddresses = []
    for line in output.split("\n"):
        if "Nmap scan report" in line:
            ipAddresses.append(line.split(" ")[-1])

    print(output)
    print(ipAddresses)
    return ipAddresses

def getNetworkInformation():
    print(socket.gethostbyname(socket.gethostname()))
    print([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][: 1])


scanNetwork("192.168.1.0", "24")
getNetworkInformation()
