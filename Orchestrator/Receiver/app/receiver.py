# Basic Flask app, bit hello world and bit PoC

from flask import Flask, request, render_template
app = Flask(__name__)

#from .identifier import identifier

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
    if todo == 'Identifier':
        return 'ID time'
    elif todo == 'Enricher':
        return 'Do the enricher'
    elif todo == 'Exploiter':
        return 'Start exploit'
    else:
        return 'Error: input incorrect'

