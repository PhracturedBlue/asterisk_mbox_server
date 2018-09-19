=================
AsteriskVM Server
=================
AsteriskVM is a client/server which provides an API to work with Asterisk voicemail mailboxes
This is the server code which needs to be installed on the Asterisk server and will monitor
mailbox directory for changes

Dependencies
============

* Linux >= 2.6.13
* Python >= 3.4
* Lame

Capabilities
============

* Display all metadata for all messages stored in a single mailbox
* Convert messages to text using Google's speech-to-text service
* Retrieve the audio of a message in MP3 format
* Support both synchronous and asynchronous API

Configuration
=============
Configuration is performed via the config.ini file

Parameters
----------
* **host** *(Optional)*: The IP address to listen on for client requests. This defaults to all IP addresses on the server. To listen only locally, choose 127.0.0.1
* **port** *(Optional)*: The port to listen on for client requests. Defaults to 12345.
* **password** *(Required)*: A password shared between client and server. Use only alpha-numeric characters and spaces
* **mbox_path** *(Required)*: The path to the storage location of mailbox files. This is typically /var/spool/asterisk/voicemail/default/<mailbox>/
* **cache_file** *(Required)*: A fully-qualified path to a file thht can be written by the server containing transcriptions of voicemails. Example: /var/spool/asterisk/transcription.cache
* **google_key** *(Required)*: Your 40 characters Google API key.
* **cdr** *(Optional)*: Where to find CDR data.  Supports various SQL databases as well as a file log.

Future work
============

* Support moving messages
* Support multiple mailboxes
* Support alternate text-to-speech providers
