import subprocess
import re

"""
This is a regex to gather each line of an nmap port scan and should be run in a manner to allow multiple matches
Group 1: Port number
Group 2: TCP/UDP
Group 3: State (open/filtered or closed/filtered or filtered or open or closed or unfilitered)
Group 4: Pretty name of the service (ssh, ftp, http, etc.)
"""
def portscan_regex():
    return r"(\d{1,6})\/([t,u][c,d]p)\s(open\/filtered|closed\/filtered|filtered|open|unfiltered|closed)\s*(.*)$"

def nmap_portscan(ipAddress):
    output = subprocess.check_output("nmap {}".format(ipAddress), shell=True).decode()
    portscan_reg = re.compile(portscan_regex(), flags=(re.M))
    matches = portscan_reg.findall(output)
    return matches

