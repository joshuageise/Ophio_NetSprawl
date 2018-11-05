import strategies
from selector import selectExploit

def main():
    sample_http = {
        "os": "Linux 7",
        "ports": [
        {
            "portNum": 80,
            "protocol": "TCP",
            "status": "open",
            "prettyName": "HTTP"
        }
        ]
    }
    sample_ssh = {
        "os": "Linux 7",
        "ports": [
        {
            "portNum": 22,
            "protocol": "TCP",
            "status": "open",
            "prettyName": "SSH"
        }
        ]
    }
    sample_otro = {
        "os": "Linux 7",
        "ports": [
        {
            "portNum": 123,
            "protocol": "TCP",
            "status": "open",
            "prettyName": "Other"
        }
        ]
    }

    strategy = strategies.Port_Num_Strategy(["ssh_exploit", "http_exploit"])
    selectExploit(strategy, sample_ssh)
    selectExploit(strategy, sample_http)
    selectExploit(strategy, sample_otro)


if __name__ == '__main__':
    main()
