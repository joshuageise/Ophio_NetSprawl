import json
import Identifier.hostdiscovery as hostdiscovery
import Identifier.networkinfo as networkinfo

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
            except:
                continue
    return json.dumps(hosts)
