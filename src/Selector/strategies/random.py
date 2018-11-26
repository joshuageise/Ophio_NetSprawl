from .strategy import Strategy
import random

class RandomStrategy(Strategy):
    """ Recommends exploits in a random order. """

    def __init__(self, exploits:list):
        self.exploits = exploits

    def search(self, target_data:dict):
        return random.shuffle(self.exploits)

    def update(self, target_data:dict, weights:dict, exploit_name:str, result:bool):
        pass
