""" asteriskvm_server.py -- Do stuff"""

import sys
import os
import socket
import select
import hashlib
import pickle
import configparser
import logging
import subprocess
import json

from threading import Thread

import speech_recognition as sr
import inotify.adapters

import asteriskvm.commands as cmd
from asteriskvm.utils import PollableQueue, recv_blocking

def _parse_request(msg):
    """Parse request from client"""
    request = {}
    request['cmd'] = msg[0]
    request['dest'] = msg[1]
    request['sha'] = msg[2:66].decode('utf-8')
    return request

def _mp3(fname):
    """Convert WAV to MP3 using LAME"""
    try:
        process = subprocess.Popen(["lame", "--abr", "24", "-mm", "-h", "-c",
                                    "--resample", "22.050", "--quiet", fname, "-"],
                                   stdout=subprocess.PIPE)
        result = process.communicate()[0]
        return result
    except OSError:
        logging.exception("Failed To execute lame")
        return

class Connection(Thread):
    """Thread to handle a single TCP conection"""
    def __init__(self, conn, status, mboxqueue, password):
        Thread.__init__(self)

        self.conn = conn
        self.status = status
        self.mboxq = mboxqueue
        self.password = password
        self.accept_pw = False

    def _sha_to_fname(self, sha):
        """Find fname from sha256"""
        for fname in self.status:
            if sha == self.status[fname]['sha']:
                return fname
        return None

    def _send(self, command, msg):
        """Send message prefixed by length"""
        msglen = len(msg)
        msglen = bytes([msglen >> 24,
                        0xff & (msglen >> 16),
                        0xff & (msglen >> 8),
                        0xff & (msglen >> 0)])
        self.conn.send(bytes([command]) + msglen + msg)

    def _handle_request(self, request):
        if request['cmd'] == cmd.CMD_MESSAGE_PASSWORD:
            self.accept_pw = self.password == request['sha']
            logging.info("Password accepted")
        if not self.accept_pw:
            logging.warning("Password rejected")
            self._send(cmd.CMD_MESSAGE_PASSWORD, b'FAIL')
        elif request['cmd'] == cmd.CMD_MESSAGE_LIST:
            logging.debug("Requested Message List")
            self._send(cmd.CMD_MESSAGE_LIST, json.dumps(self.status).encode('utf-8'))
        elif request['cmd'] == cmd.CMD_MESSAGE_MP3:
            fname = self._sha_to_fname(request['sha'])
            logging.debug("Requested MP3 for %s ==> %s", request['sha'], fname)
            msg = b''
            if fname:
                msg = _mp3(fname + ".wav")
            self._send(cmd.CMD_MESSAGE_MP3, msg)

    def run(self):
        """Thread main loop"""
        while True:
            readable, dummy_w, dummy_e = select.select([self.conn, self.mboxq], [], [])
            if self.conn in readable:
                try:
                    request = _parse_request(recv_blocking(self.conn, 66))
                except RuntimeError:
                    logging.warning("Connection closed")
                    break
                logging.debug(request)
                self._handle_request(request)

            if self.mboxq in readable:
                self.status = self.mboxq.get()
                self.mboxq.task_done()
                #logging.info(self.status)
                self._send(cmd.CMD_MESSAGE_LIST, json.dumps(self.status).encode('utf-8'))

def _sha256(fname):
    """Get SHA256 sum of a file contents"""
    sha = hashlib.sha256()
    with open(fname, "rb") as infile:
        for chunk in iter(lambda: infile.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

def _parse_msg_header(fname):
    """Parse asterisk voicemail metadata"""
    ini = configparser.ConfigParser()
    ini.read(fname)
    try:
        return dict(ini.items('message'))
    except configparser.NoSectionError:
        logging.exception("Couldn't parse: %s", fname)
        return

class WatchMailBox(Thread):
    """Thread to watch for new/removed messages in a mailbox"""
    def __init__(self, mbox_queue, path, stt_file, sr_keys):
        Thread.__init__(self)

        self.mbox_queue = mbox_queue
        self.path = path
        self.stt_file = stt_file
        self.sr_keys = sr_keys
        self.subdirs = ('INBOX', 'Old', 'Urgent')
        self.speech = sr.Recognizer()
        self.cache = {}
        if os.path.isfile(stt_file):
            with open(stt_file, 'rb') as infile:
                self.cache = pickle.load(infile)
        self._save_cache()
        self.inot = inotify.adapters.Inotify()
        for subdir in self.subdirs:
            directory = os.path.join(self.path, subdir)
            self.inot.add_watch(directory.encode('utf-8'))

    def _save_cache(self):
        """Save cache data"""
        with open(self.stt_file, 'wb') as outfile:
            pickle.dump(self.cache, outfile, pickle.HIGHEST_PROTOCOL)

    def _speech_to_text(self, fname):
        """Convert WAV to text"""
        txt = ""
        logging.debug('STT ' + fname)
        try:
            with sr.WavFile(fname) as source:
                audio = self.speech.record(source) # read the entire WAV file
                txt += self.speech.recognize_google(audio, key=self.sr_keys['GOOGLE_KEY'])
        except sr.UnknownValueError:
            txt += "Google Speech Recognition could not understand audio"
        except sr.RequestError as exception:
            txt += "Could not request results from " \
                   "Google Speech Recognition service; {0}".format(exception)
        logging.debug("Parsed %s --> %s", fname, txt)
        return txt

    def _get_mbox_status(self):
        """Parse all messages ina mailbox"""
        data = {}
        for subdir in self.subdirs:
            directory = os.path.join(self.path, subdir)
            logging.debug('Reading: ' + directory)
            if not os.path.isdir(directory):
                continue
            for filename in os.listdir(directory):
                filename = os.path.join(directory, filename)
                if not os.path.isfile(filename):
                    continue
                basename, ext = os.path.splitext(filename)
                logging.debug('Parsing: %s -- %s', basename, ext)
                if basename not in data:
                    data[basename] = {}
                if ext == '.txt':
                    data[basename]['info'] = _parse_msg_header(filename)
                elif ext == '.wav':
                    data[basename]['sha'] = _sha256(filename)
                    data[basename]['wav'] = filename
        for fname, ref in data.items():
            if 'info' not in ref or 'sha' not in ref or not os.path.isfile(fname + '.wav'):
                logging.debug('Message is not complete: ' + fname)
                del data[fname]
                continue
            sha = ref['sha']
            if sha not in self.cache:
                self.cache[sha] = {}
            if 'txt' not in self.cache[sha]:
                self.cache[sha]['txt'] = self._speech_to_text(fname + '.wav')
                self._save_cache()
            logging.debug("SHA (%s): %s", fname, sha)
            ref['text'] = self.cache[sha]['txt']
        return data

    def run(self):
        """Main Loop"""
        status = self._get_mbox_status()
        self.mbox_queue.put(status)
        try:
            for event in self.inot.event_gen():
                if event is not None:
                    (_header, type_names, _watch_path, _filename) = event
                    if type_names in ('IN_DELETE', 'IN_CLOSE_WRITE',
                                      'IN_MOVED_FROM', 'IN_MOVED_TO'):
                        status = self._get_mbox_status()
                        self.mbox_queue.put(status)
        finally:
            for subdir in self.subdirs:
                directory = os.path.join(self.path, subdir)
                self.inot.remove_watch(directory.encode('utf-8'))

# pylint: disable=too-many-locals
def main():
    """Main thread"""
    logging.basicConfig(format="%(levelname)-10s %(message)s", level=logging.DEBUG)

    if len(sys.argv) != 2:
        print("Must specify configuration file")
        sys.exit()
    config = configparser.ConfigParser()
    config.read(sys.argv[1])

    password = config.get('default', 'password')
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        soc.bind(('', config.getint('default', 'port')))
    except socket.error:
        logging.exception('Bind failed.')
        sys.exit()
    soc.listen(10)

    mbox_queue = PollableQueue()
    mailbox = WatchMailBox(mbox_queue,
                           config.get('default', 'mbox_path'),
                           config.get('default', 'cache_file'),
                           {'GOOGLE_KEY': config.get('default', 'google_key')})
    mailbox.setDaemon(True)
    mailbox.start()

    clients = []
    status = {}
    while True:
        readable, dummy_writable, dummy_errored = select.select([soc, mbox_queue], [], [])
        if soc in readable:
            conn, addr = soc.accept()
            ipaddr, port = str(addr[0]), str(addr[1])
            logging.info('Accepting connection from ' + ipaddr + ':' + port)

            try:
                que = PollableQueue()
                thread = Connection(conn, status, que, password)
                thread.setDaemon(True)
                thread.start()
                clients.append((thread, que))
            except Exception: # pylint: disable=broad-except
                logging.exception("Terible error!")
        clients = [(thread, que) for thread, que in clients if thread.isAlive()]
        if mbox_queue in readable:
            status = mbox_queue.get()
            for thread, que in clients:
                que.put(status)
            mbox_queue.task_done()
    soc.close()


if __name__ == '__main__':
    main()
