=================
AsteriskVM Server
=================
AsteriskVM is a client/server which provides an API to work with Asterisk voicemail mailboxes
This is the server code which needs to be installed on the Asterisk server and will monitor
mailbox directory for changes

Dependencies
============

* Linux ≥ 2.6.13
* Python ≥ 3.4
* Lame

Capabilities
============

* Display all metadata for all messages stored in a single mailbox
* Convert messages to text using Google's speech-to-text service
* Retrieve the audio of a message in MP3 format
* Support both synchronous and asynchronous API

Future work
============

* Support deleting messages
* Support moving messages
* Support multiple mailboxes
* Support alternate text-to-speech providers
