# Serval REST API

serval-dna presents an HTTP REST API for interacting with Serval MeshMS and Serval Rhizome bundles

The following documentation assumes servald is running on localhost on the default port (4110).

CORS (Cross-Origin Resource Sharing) support has been implemented in serva-dna. Cross-origin requests are accepted from any port on 'localhost' or '127.0.0.1'.

## Authentication

The REST API implements basic authentication, configured in your servald config file.

To view the syntax for adding users to this config file, dump the servald config schema

    ./servald config schema

## MeshMS API Methods

### List Conversations

    GET /restful/meshms/<sid>/conversationlist.json

### List Messages (view Conversation)

    GET /restful/meshms/<sid1>/<sid2>/messagelist.json

### List New Messages (since <message token>)

    GET /restful/meshms/<sid1>/<sid2>/newsince/<token>/messagelist.json


### Send New Message

Used to send a message from one SID to another. Does not require an existing conversation to send messages.

    POST /restful/meshms/<sid1>/<sid2>/sendmessage

The POST attributes that may be used are:
 
 * message: The message being sent.

 When sending this message, SID1 must be an identity present in your keyring.

### Mark Messages as "Read"

Serval stores an offset for each conversation indicating up to which message has been read. This means that specific messages cannot be marked as read, instead every message up to a point is marked as read.

To mark all messages to a SID as read

    POST /restful/meshms/<sid>/readall

To mark all messages in a conversation as read

    POST /restful/meshms/<sid1>/<sid2>/readall

To make all messages in a conversation up to a specific message (by its conversation offset) as read:

    POST /restful/meshms/<sid1>/<sid2>/recv/<offset>/read

## Rhizome API Methods

TODO. For now, see the rhizomerestful [tests](../tests/rhizomerestful)


## JSON format

Servald compresses the JSON it outputs to remove redundant headings. Hence, the output JSON looks like this:

    {
        "header":[".token","_id","service","id","version","date",".inserttime",".author",".fromhere","filesize","filehash","sender","recipient","name"],
        "rows":[
            ["-luCgeURRKqvbRKQilANXwcAAAAAAAAA",7,"file","F81645C6693A98EB4D2727A7A3D9F478FF77CC60F68949679BFD2A7C65A29E89",1384921558580,1384921558581,1384921558648,"A8BFD18D5BF6E005E96E62188F553F0149B10AD03B47B7A35181457B2A1ABF69",1,1006,"A49C795AE4687CB14F6F1F01265C1DC6472935B125F52ADE4F166A31770E508AF2E0AF9F48D9F6826D60C7B5B820C63028EFD78AD32B9EBA5E43A2B60D74C9E8",null,null,"file6"],
            ...
        ]
    }

To decompress this JavaScript, use a function similar to the following

    function decompressServalJson(compressed) {
        var header = compressed.header;
        var rows = compressed.rows;

        var records = [];

        if (header === undefined || rows === undefined) {
            throw "Undefined rows or headers for Serval object\n" + JSON.stringify(compressed);
        }

        for (var i = 0; i < rows.length; i++) {
            var row = rows[i];
            if (row.length != header.length) {
                console.error("Illegal row/header pair in Serval object" +
                    "\n" + JSON.stringify(header) +
                    "\n" + JSON.stringify(row));
                continue;
            }

            var record = {};
            for (var j = 0; j < header.length; j++) {
                record[header[j]] = row[j];
            }
            records.push(record);
        }
        return records;
    } 

## POST requests

Servald only allows POST requests to be [submitted using multipart/form-data](https://github.com/servalproject/serval-dna/issues/82) as blobs with explicit encoding.

To ensure Servald reponds correctly to your 

An example request to send a message using CURL is shown below.

   curl \
         --basic --user harry:potter \
         --form "message=Hello World;type=text/plain;charset=utf-8" \
         "/restful/meshms/<sid1>/<sid2>/sendmessage"


The equivalent JavaScript for sending this request would be

	var sid1 = 'foo';
	var sid2 = 'bar';
	
	var address = "/restful/meshms/" + sid1 +"/" + sid2 + "/sendmessage";

	var username = 'demouser';
	var password = 'demopassword';

	var params = new FormData();
    params.append('message', 'Hello World');

    var xhr = new XMLHttpRequest();

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            console.log(xhr.response);
        }
    };

	xhr.open("POST", address, true);
	xhr.setRequestHeader('Authorization', 'Basic ' + btoa(username + ":" + password));
	xhr.send(params);

