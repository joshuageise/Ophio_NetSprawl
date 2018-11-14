# Basic Flask app, bit hello world and bit PoC
#!/usr/bin/python3
from flask import Flask, request, render_template
app = Flask(__name__)

import Identifier
import Enricher
import Exploiter

import json
from pymongo import MongoClient
from metasploit.msfrpc import MsfRpcClient


client = MongoClient()
db = client["NetSprawl"]
Net_map = db["Map"]
exploits = db["Exploit"]


@app.route('/')
def root():
    return render_template('index.html')

# @app.route('/receive', methods=['GET', 'POST'])
# def receive():
#
#     if request.content_length == 0 or not request.is_json:
#         # return a 400 code
#         return "json required", 400
#
#     else:
#         # parse json sent, plus other interesting info
#         json = request.json
#         addr = request.remote_addr
#
#         # forward it to the database? call or return to the enricher?
#         # drop it as a file for now
#         with open("Reports/{}".format(addr), "w") as f:
#             f.write(str(json))
#
#         # return a 200
#         return "received", 200

@app.route('/do')
def todo():
    todo = request.args.get('do')
    host = request.args.get('host')
    target = request.args.get('target')
    exploit = request.args.get('exploit')

    if todo == 'Identifier':
        identifyResults = Identifier.scanCurrentNetwork()
        identifyDict = json.loads(identifyResults)
        Net_map.insert(identifyDict)
        return identifyResults

    elif todo == 'Enricher' and host != '':
        enrichResults = Enricher.scanHostForInfo(host)
        return str(enrichResults)

    elif todo == 'Exploiter' and target != '' and exploit != '':
        msClient = MsfRpcClient("pass")
        exploitResults = Exploiter.callExploit(msClient, exploit, target)
        return str(exploitResults)

    else:
        return 'Error: input incorrect'
