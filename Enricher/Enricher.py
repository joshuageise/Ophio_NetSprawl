import osscan
import portscan
import json

def scanHostForInfo(ipAddress:str):
    os = ""
    ports = []
    for func in osscan.os_scans:
        try:
            os = func(ipAddress)
            break
        except:
            continue
    for func in portscan.port_scans:
        try:
            portResults = func(ipAddress)
            portDicts = []
            for result in portResults:
                newDict = {}
                newDict["portNum"] = result[0]
                newDict["protocol"] = result[1]
                newDict["status"] = result[2]
                newDict["prettyName"] = result[3]
                portDicts.append(newDict)
            ports = portDicts
            break
        except:
            continue
    ports.insert(0, os)
    return json.dumps(ports)

def scanHostsForInfo(ipAddresses:list):
    pass
