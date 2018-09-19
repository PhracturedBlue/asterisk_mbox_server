"""asterisk_mbox_server.py -- Do stuff."""

import sys
import socket
import select
import configparser
import logging
import json
import time
import argparse
import zlib

from threading import Thread
from asterisk_mbox_server.mbox import WatchMailBox
from asterisk_mbox_server.cdr import WatchCDR

import asterisk_mbox.commands as cmd
from asterisk_mbox.utils import (PollableQueue, recv_blocking,
                                 encode_password, compare_password,
                                 decode_from_sha)

__version__ = "0.5.3"


def _parse_request(msg):
    """Parse request from client."""
    request = {}
    request['cmd'] = msg[0]
    request['dest'] = msg[1]
    request['sha'] = msg[2:66].decode('utf-8')
    return request


class Connection(Thread):
    """Thread to handle a single TCP conection."""

    def __init__(self, conn, mbox, cdr, password):
        """Initialize."""
        # pylint: disable=too-many-arguments
        Thread.__init__(self)

        self.conn = conn
        self.mbox = mbox
        self.cdr = cdr
        self.mboxq = PollableQueue()
        self.password = password
        self.accept_pw = False

    def queue(self):
        """Fetch queue object."""
        return self.mboxq

    def _build_msg_list(self):
        """Send a sanitized list to the client."""
        result = []
        blacklist = ["wav"]
        status = self.mbox.get_mbox_status()
        for _k, ref in status.items():
            result.append({key: val for key, val in ref.items()
                           if key not in blacklist})
        return result

    @staticmethod
    def _build_cdr(entries, start=0, count=-1, sha=None):
        """Extract requested info from cdr list."""
        if sha is not None:
            msg = decode_from_sha(sha)
            start, count = [int(item) for item in msg.split(b',')]
        if not start or start < 0:
            start = 0
        if start >= len(entries) or count == 0:
            return msg

        if count < 0 or count + start > len(entries):
            end = len(entries)
        else:
            end = start + count
        return entries[start:end]

    def _send(self, command, msg):
        """Send message prefixed by length."""
        msglen = len(msg)
        msglen = bytes([msglen >> 24,
                        0xff & (msglen >> 16),
                        0xff & (msglen >> 8),
                        0xff & (msglen >> 0)])
        self.conn.send(bytes([command]) + msglen + msg)

    def _handle_request(self, request):
        if request['cmd'] == cmd.CMD_MESSAGE_PASSWORD:
            self.accept_pw, msg = compare_password(self.password,
                                                   request['sha'])
            if self.accept_pw:
                self._send(cmd.CMD_MESSAGE_VERSION,
                           __version__.encode('utf-8'))
                logging.info("Password accepted")
            else:
                self._send(cmd.CMD_MESSAGE_ERROR, msg.encode('utf-8'))
                logging.warning("Password rejected: %s", msg)
        elif not self.accept_pw:
            logging.warning("Bad Password")
            self._send(cmd.CMD_MESSAGE_ERROR, b'bad password')
        elif request['cmd'] == cmd.CMD_MESSAGE_LIST:
            logging.debug("Requested Message List")
            self._send(cmd.CMD_MESSAGE_LIST,
                       json.dumps(self._build_msg_list()).encode('utf-8'))
        elif request['cmd'] == cmd.CMD_MESSAGE_MP3:
            msg = self.mbox.mp3(request['sha'])
            if msg:
                self._send(cmd.CMD_MESSAGE_MP3, msg)
            else:
                logging.warning("Couldn't find message for %s", request['sha'])
                self._send(cmd.CMD_MESSAGE_ERROR,
                           "Could not find requested message")
        elif request['cmd'] == cmd.CMD_MESSAGE_CDR_AVAILABLE:
            if not self.cdr:
                self._send(cmd.CMD_MESSAGE_ERROR, b'CDR Not enabled')
                return
            self._send(cmd.CMD_MESSAGE_CDR_AVAILABLE,
                       json.dumps({'count': self.cdr.count()}).encode('utf-8'))
        elif request['cmd'] == cmd.CMD_MESSAGE_CDR:
            if not self.cdr:
                self._send(cmd.CMD_MESSAGE_ERROR, b'CDR Not enabled')
                return
            entries = self._build_cdr(self.cdr.entries(), sha=request['sha'])
            msg = {'keys': self.cdr.keys(), 'entries': entries}
            self._send(cmd.CMD_MESSAGE_CDR,
                       zlib.compress(json.dumps(msg).encode('utf-8')))

    def run(self):
        """Thread main loop."""
        while True:
            readable, _w, _e = select.select([self.conn, self.mboxq], [], [])
            if self.conn in readable:
                try:
                    request = _parse_request(recv_blocking(self.conn, 66))
                except RuntimeError:
                    logging.warning("Connection closed")
                    break
                logging.debug(request)
                self._handle_request(request)

            if self.mboxq in readable:
                msgtype = self.mboxq.get()
                self.mboxq.task_done()
                if msgtype == 'mbox':
                    self._send(cmd.CMD_MESSAGE_LIST,
                               json.dumps(self._build_msg_list())
                               .encode('utf-8'))
                elif msgtype == 'cdr':
                    self._send(cmd.CMD_MESSAGE_CDR_AVAILABLE,
                               json.dumps({'count': self.cdr.count()})
                               .encode('utf-8'))


class AsteriskMboxServer:  # pylint: disable=too-few-public-methods
    """Monitor Asterisk Mailbox."""

    def __init__(self):
        """Initialize."""
        args = self._parse_args()
        logging.basicConfig(level=logging.DEBUG
                            if args.verbose else logging.INFO)

        self._opts = self._config(args.cfg)
        self._soc = self._setup_socket()

        self._mailbox = WatchMailBox(self._opts['mbox_path'],
                                     self._opts['cache_file'],
                                     {'GOOGLE_KEY': self._opts['google_key']})
        self._mailbox.setDaemon(True)
        self._mailbox.start()

        self._cdr = None
        if self._opts['cdr']:
            self._cdr = WatchCDR(self._opts['cdr'],
                                 self._opts['poll_interval'])
            self._cdr.setDaemon(True)
            self._cdr.start()

        self._clients = []

    @staticmethod
    def _config(fname):
        config = configparser.ConfigParser()
        config.read(fname)
        config = config["default"]
        opts = {}
        password = config.get('password')
        opts['password'] = encode_password(password)
        opts['port'] = config.getint('port', 12345)
        opts['mbox_path'] = config.get('mbox_path')
        opts['cache_file'] = config.get('cache_file', 'asteriskmbox.pkl')
        opts['google_key'] = config.get('google_key')
        opts['ipaddr'] = config.get('ipaddr', '')
        opts['min_interval'] = config.getint('min_interval', 10)
        opts['cdr'] = config.get('cdr', None)
        opts['poll_interval'] = config.getint('poll_interval', 5)
        return opts

    @staticmethod
    def _parse_args():
        """Parse cmdline arguments."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--cfg", help="Path to configuration file")
        parser.add_argument("-v", "--verbose", help="Turn on debug logging",
                            action='store_true')
        return parser.parse_args()

    def _setup_socket(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            soc.bind((self._opts['ipaddr'], self._opts['port']))
        except socket.error:
            logging.exception('Bind failed.')
            sys.exit()
        soc.listen(10)
        return soc

    def _connection(self):
        """Initialize a new connection."""
        conn, addr = self._soc.accept()
        ipaddr, port = str(addr[0]), str(addr[1])
        logging.info('Accepting connection from ' + ipaddr + ':' + port)

        try:
            thread = Connection(conn, self._mailbox, self._cdr,
                                self._opts['password'])
            thread.setDaemon(True)
            thread.start()
            self._clients.append(thread)
        except Exception:                      # pylint: disable=broad-except
            logging.exception("Terible error!")

    def _handle_cdr_update(self):
        """Read CDR update."""
        queue = self._cdr.queue()
        queue.get()
        queue.task_done()
        for thread in self._clients:
            thread.queue().put('cdr')

    def _handle_mbox_update(self, timeout, last_time, readable):
        """Read Mailbox update."""
        read_mbox = False
        if readable:
            queue = self._mailbox.queue()
            queue.get()
            queue.task_done()
            if not timeout:
                if time.time() - last_time < self._opts['min_interval']:
                    last_time = time.time()
                    timeout = self._opts['min_interval']
                else:
                    read_mbox = True
        if timeout:
            if time.time() - last_time >= self._opts['min_interval']:
                read_mbox = True
            else:
                timeout = last_time + self._opts['min_interval'] - time.time()
        if read_mbox:
            self._mailbox.update()
            for thread in self._clients:
                thread.queue().put('mbox')
            last_time = time.time()
            timeout = None
        return timeout, last_time

    def loop(self):
        """Run main thread."""
        timeout = None
        last_time = 0

        sockets = [self._soc, self._mailbox.queue()]
        if self._cdr:
            sockets.append(self._cdr.queue())
        while True:
            readable, _w, _e = select.select(sockets, [], [], timeout)

            if self._soc in readable:
                self._connection()

            self._clients = [thread for thread in self._clients
                             if thread.isAlive()]

            if self._cdr and self._cdr.queue() in readable:
                self._handle_cdr_update()

            timeout, last_time = self._handle_mbox_update(
                timeout, last_time,
                self._mailbox.queue() in readable)

        self._soc.close()


def main():
    """Execute main application."""
    AsteriskMboxServer().loop()


if __name__ == '__main__':
    main()
