import ../Exploiter
import strategies
from metasploit.msfrpc import MsfRpcClient

###
# current feature set:
# - operating system
# - list of open ports
###

def selectExploit(strategy:strategies.Strategy, msfClient:MsfRpcClient, target_data:list):
    # get list of exploits
    # try in order, call update after each
    # loop until success or none left

    exploits = strategy.search(target_data)
    for exploit in exploits:
        result = testExploit(target_data, exploit) # TODO connect this to Exploiter
        strategy.update(target_data, exploit, result)
        if result:
            break

    ### debug output
    # if result:
    #     print("successfully exploited a thing")
    # else:
    #     print("could not exploit the thing")

    return result #or whatever else callExploit() returns


# for testing
def testExploit(target_data:dict, exploit:str):
    if exploit == 'http_exploit':
        for port in target_data["ports"]:
            if int(port["portNum"]) == 80:
                return True
    elif exploit == 'ssh_exploit':
        for port in target_data["ports"]:
            if int(port["portNum"]) == 22:
                return True
    return False
