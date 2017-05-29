MeshMB REST API
===============
[Serval Project][], February 2016

Introduction
------------

[MeshMB][] is a service in the [Serval Mesh network][] that provides
distributed one-to-all messaging using [Rhizome][] as transport.

The [Serval DNA][] daemon that runs on every node gives applications access to
the MeshMB service via the **MeshMB REST API** described in this document.

### Basic concepts

#### Feed

An unencrypted rhizome journal. With the same internal format as a MeshMS message ply.

Each feed has a name, set in the rhizome manifest. 

The Bundle ID of the feed, is the author of the bundle. In other words, 
the bundle secret is the same secret stored in the serval keyring to represent an identity.

### POST /restful/meshmb/ID/sendmessage

Append a new message to the feed.

### GET /restful/meshmb/FEEDID/messagelist.json

List the messages in any feed.

### GET /restful/meshmb/FEEDID/newsince[/TOKEN]/messagelist.json

List messages from a feed as they arrive.

### GET /restful/meshmb/ID/feedlist.json

List the feeds that you have subscribed to.

### GET /restful/meshmb/ID/activity.json

List the messages of all subscribed feeds, threaded in the order they originally arrived.

### GET /restful/meshmb/ID/activity[/TOKEN]/activity.json

List the messages of all subscribed feeds, as they arrive.

### POST /restful/meshmb/ID/follow/FEEDID

Start following this Feed.

### POST /restful/meshmb/ID/ignore/FEEDID

Stop following this Feed.

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
