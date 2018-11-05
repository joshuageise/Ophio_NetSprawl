import re
import subprocess
"""
This regex has one capture group, it finds the line starting with "Running : " and then grabs the value
"""
def os_regex():
    return r"^Running:\s*(.*)$"

def nmap_osscan(ipAddress:str):
    output = subprocess.check_output("sudo nmap -O {}".format(ipAddress), shell=True).decode()
    os_reg = re.compile(os_regex(), flags=re.M)
    os = os_reg.findall(output)
    if len(os) < 1:
        return "unknown"
    elif os == []:
        return "unknown"
    else:
        return os[0]
