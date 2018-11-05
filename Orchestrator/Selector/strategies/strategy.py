class Strategy:
    """ Generic interface for a strategy, allowing specialized representations to be used interchangeably. """
    def __init__(self, exploits:str):
        self.exploits = exploits

    def search(self, target_data:dict):
        return self.exploits

    def update(self, target_data:dict, exploit_name:str, result:bool):
        pass
