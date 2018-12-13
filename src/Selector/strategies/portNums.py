from .strategy import Strategy

class PortNumStrategy(Strategy):
    """ Evaluates the list of open ports and recommends exploits based on prior success. """

    def __init__(self, exploits:list):
        self.weights = {}
        for exploit_name in exploits:
            self.weights[exploit_name] = {}

    """ ranks exploits by past success given list of open ports """
    def search(self, target_data:list):
        weight_sums = {}

        for exploit in self.weights:
            weight_sums[exploit] = 0
            if len(target_data) > 1:
                for port in target_data[1:]:
                    port_num = int(port["portNum"])
                    weight_sums[exploit] += self.weights[exploit].get(port_num, 0) # 0 if not present

        exploits = sorted(weight_sums, key=(lambda key: weight_sums[key]), reverse=True)
        return exploits

    """ increases weights for each port on exploit success, decreases on failure """
    def update(self, target_data:list, exploit_name:str, result:bool):
        if len(target_data) > 1:
            for port in target_data[1:]:
                port_num = int(port["portNum"])

                if result:
                    updated = self.weights[exploit_name].get(port_num, 4)
                    updated = min(updated + 1, 10)
                    self.weights[exploit_name][port_num] = updated
                else:
                    updated = self.weights[exploit_name].get(port_num, 0)
                    updated = max(updated - 1, 0)
                    self.weights[exploit_name][port_num] = updated

    """ returns a dict containing the strategy's state """
    def export(self):
        # format port numbers to str for compatibility
        weights = self.weights
        formatted = {}
        for exploit in weights.keys():
            formatted[exploit] = {}
            for port_num in weights[exploit].keys():
                formatted[exploit][str(port_num)] = weights[exploit][port_num]

        return {"strategy" : "port nums", "weights" : formatted}
