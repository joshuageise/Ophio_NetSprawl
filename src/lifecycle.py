import Identifier
import Enricher
import Orchestrator
import Exploiter

def main():
    print("hello world")

    # setup
    # check for dependencies
    # check for legally scanned network?
    # copy + zip identifier for post-exploits
    # connect to database
    # initialize exploits + data for selector
    # initialize logging

    # identifier
    # call scanCurrentNetwork on initial host
    # log results of scan
    # add host info to database

    # enricher
    # call scanHostsForInfo on list of hosts, excluding self
    # log results of scans
    # append information to host records in database

    # selector/exploiter
    # call search on enriched host data
    # attempt exploits in recommended order
    # log results and update selector after each exploit run
    # append exploit status (exploit used, MS session) to host records

    # post-exploits
    # drop and run identifier on exploited boxes
    # add new hosts to records + database
    # enrich and exploit new hosts as usual

    # repetition
    # each host should be identified, enriched, exploited, and scanned from:
    # a) seperate queues for each stage, evaluated independently
    # b) single queue, each host evaluated straight through
    #
    # identifiers should be rerun periodically to identify new hosts

if __name__ == '__main__':
    main()
