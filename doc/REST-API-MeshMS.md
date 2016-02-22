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

#### Conversation

TBC

#### Ply

### GET /restful/meshms/RECIPIENTSID/conversationlist.json

TBC

### GET /restful/meshms/SENDERSID/RECIPIENTSID/messagelist.json

TBC

### GET /restful/meshms/SENDERSID/RECIPIENTSID/newsince/TOKEN/messagelist.json

TBC

### POST /restful/meshms/SENDERSID/RECIPIENTSID/sendmessage

TBC


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
