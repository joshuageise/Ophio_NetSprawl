# Basic Flask app, bit hello world and bit PoC
#!/usr/bin/python3
from flask import Flask, request, render_template
app = Flask(__name__)

import sys
import os
import Identifier
import Enricher
import Exploiter
from pymongo import MongoClient


client = MongoClient()
db = client['Net_Map']
Net_map = db.Net_Map

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/receive', methods=['GET', 'POST'])
def receive():

    if request.content_length == 0 or not request.is_json:
        # return a 400 code
        return "json required", 400

    else:
        # parse json sent, plus other interesting info
        json = request.json
        addr = request.remote_addr

        # forward it to the database? call or return to the enricher?
        # drop it as a file for now
        with open("Reports/{}".format(addr), "w") as f:
            f.write(str(json))

        # return a 200
        return "received", 200

@app.route('/do')
def todo():
    todo = request.args.get('do')
    host = request.args.get('host')
    if todo == 'Identifier':
        cool = Identifier.scanCurrentNetwork()
        #Net_map.insert_one(str(cool))
        return str(cool)
    elif todo == 'Enricher':
        if host!='':
            rich = Enricher.scanHostForInfo(host)
            return str(rich)
        else:
            return 'Error: Enicher'
    elif todo == 'Exploiter':
        return 'Start exploit'
    else:
        rich = Enricher.scanHostForInfo(host)
        return str(rich)

        #return 'Error: input incorrect'




