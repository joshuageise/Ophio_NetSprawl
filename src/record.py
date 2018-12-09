class Record:
    STATUS_UNEXPLORED = 0
    STATUS_SUCCESS = 1
    STATUS_FAILURE = 2

    """ Object to represent a discovered host throughout its lifecycle. """
    def __init__(self, interfaces, parentId):
        self.id = None
        self.interfaces = interfaces
        self.parentId = parentId
        self.os = None
        self.openPorts = None
        self.exploitStatus = {
            "statusCode": self.STATUS_UNEXPLORED,
            "exploitUsed": None,
            "msfSessionId": None
        }

    def toDict(self):
        dict = {
            "interfaces": self.interfaces,
            "parentId": self.parentId,
            "os": self.os,
            "openPorts": self.openPorts,
            "exploitStatus": self.exploitStatus
        }
        if self.id != None:
            dict["_id"] = self.id
        return dict
