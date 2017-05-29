MeshMS REST API
===============
[Serval Project][], February 2016

Introduction
------------

[MeshMS][] is a service in the [Serval Mesh network][] that provides secure,
distributed one-to-one messaging using [Rhizome][] as transport.

The [Serval DNA][] daemon that runs on every node gives applications access to
the [MeshMS][] service via the **MeshMS REST API** described in this document.

### Basic concepts

#### Ply

In rhizome, each author can only update rhizome bundles that they first created. 
A ply is a rhizome journal bundle where each participant records their outgoing messages, 
and any other changes to the conversation.

A ply can contain the following types of records;

 * ACK - A pointer to a range of content within another ply.
 * MESSAGE - A plain text message encoded in UTF-8.
 * TIME - A timestamp related to the previous record.

#### Conversation

A MeshMS conversation consists of one or two message ply's. Each participant sets
the sender and recipient manifest fields to the identities of the two parties in the 
conversation.

Both ply's are encrypted such that only the sender and recipient can read their contents.

Whenever a new MESSAGE is detected on an incoming ply, a new ACK record is written to the
end of the outgoing ply. This is used to indicate successful delivery, and to thread the
display of messages in the conversation.

There is no central server to assign a common ordering to messages in a conversation,
both parties will see their outgoing messages threaded with received messages in the order
they arrived locally. 

### GET /restful/meshms/SENDERSID/conversationlist.json

List all the conversations for which SENDERSID is either the sender or receiver of a ply.
SENDERSID must be an identity in the serval keyring.

### GET /restful/meshms/SENDERSID/RECIPIENTSID/messagelist.json

List the messages in the conversation between SENDERSID and RECIPIENTSID.

### GET /restful/meshms/SENDERSID/RECIPIENTSID/newsince[/TOKEN]/messagelist.json

List new messages in the conversation between SENDERSID and RECIPIENTSID as they arrive.

### POST /restful/meshms/SENDERSID/RECIPIENTSID/sendmessage

Send a new message from SENDERSID to RECIPIENTSID.

-----
**Copyright 2015 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval Mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: ../README.md
[REST-API]: ./REST-API.md
[MeshMS]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:meshms
[Rhizome]: ./REST-API-Rhizome.md
[200]: ./REST-API.md#200-ok
[201]: ./REST-API.md#201-created
[202]: ./REST-API.md#202-accepted
[400]: ./REST-API.md#400-bad-request
[404]: ./REST-API.md#404-not-found
[419]: ./REST-API.md#419-authentication-timeout
[422]: ./REST-API.md#422-unprocessable-entity
[423]: ./REST-API.md#423-locked
[500]: ./REST-API.md#500-server-error
