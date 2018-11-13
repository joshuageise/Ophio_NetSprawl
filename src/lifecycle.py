import Identifier
import Enricher
import Orchestrator
import Exploiter
from record import Record

import pymongo
from metasploit.msfrpc import MsfRpcClient

def main():
    ### setup
    # check for dependencies? - nmap, ms, mongo
    # check for legally scanned network?
    # copy + zip identifier for post-exploits?
    # initialize pointers for orchestration
    # connect to database
    # initialize exploits + data for selector
    # initialize logging

    hostCollection = []
    rootHost = None

    enrichQueue = []
    exploitQueue = []
    postexQueue = []

    # TODO connect to mango

    # strategy = ...



    ### identifier
    # call scanCurrentNetwork on initial host
    # log results of scan
    # identify root node
    # add host records to database

    identifyResults = Identifier.scanCurrentNetwork()
    rootInterfaces = []
    hostsDiscovered = []
    for network in identifyResults:
        rootInterfaces.append(network["network"])
        for hostIp in network["hosts"]:
            if hostIp not in rootInterfaces:
                hostsDiscovered.append(hostIp)

    rootHost = Record(rootInterfaces, None)
    # TODO insert rootHost.toDict() to db, generate + store id
    rootHost.exploitStatus["statusCode"] = Record.STATUS_SUCCESS
    rootHost.exploitStatus["exploitUsed"] = "N/A"
    hostCollection.append(rootHost)
    enrichQueue.append(rootHost)
    for hostIp in hostsDiscovered:
        hostRecord = Record([hostIp], rootHost.id)
        # TODO insert hostRecord.toDict() to db, generate + store id
        hostCollection.append(hostRecord)
        enrichQueue.append(hostRecord)


    ### enricher
    # call scanHostsForInfo on list of hosts, excluding self
    # log results of scans
    # append information to host records in database

    while len(enrichQueue) > 0:
        hostRecord = enrichQueue.pop()
        enrichResults = Enricher.scanHostForInfo(hostRecord.interfaces)
        hostRecord.os = enrichResults[0]
        hostRecord.openPorts = enrichResults[1:]
        # TODO update hostRecord, filtering by hostRecord.id
        exploitQueue.append(host)



    ### selector/exploiter
    # call search on enriched host data
    # attempt exploits in recommended order
    # log results and update selector after each exploit run
    # append exploit status (exploit used, MS session) to host records

    while len(exploitQueue) > 0:
        hostRecord = exploitQueue.pop()



    ### post-exploits
    # drop and run identifier on exploited boxes
    # add new hosts to records + database
    # enrich and exploit new hosts as usual




    ### repetition
    # each host should be identified, enriched, exploited, and scanned from:
    # a) seperate queues for each stage, evaluated independently
    # b) single queue, each host evaluated straight through
    #
    # identifiers should be rerun periodically to identify new hosts

if __name__ == '__main__':
    main()
