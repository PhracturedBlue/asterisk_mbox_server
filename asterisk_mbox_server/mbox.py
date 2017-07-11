"""Watch mailbox for new messages."""

import os
import pickle
import logging
import configparser
import hashlib

from threading import Thread

import speech_recognition as sr
import inotify.adapters

from asterisk_mbox.utils import PollableQueue


class WatchMailBox(Thread):
    """Thread to watch for new/removed messages in a mailbox."""

    def __init__(self, path, stt_file, sr_keys):
        """Initializie."""
        Thread.__init__(self)

        self.mbox_queue = PollableQueue()
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
            logging.debug("Watching Directory: %s", directory)
            self.inot.add_watch(directory.encode('utf-8'))

    def _save_cache(self):
        """Save cache data."""
        with open(self.stt_file, 'wb') as outfile:
            pickle.dump(self.cache, outfile, pickle.HIGHEST_PROTOCOL)

    def _speech_to_text(self, fname):
        """Convert WAV to text."""
        txt = ""
        logging.debug('STT ' + fname)
        try:
            with sr.WavFile(fname) as source:
                audio = self.speech.record(source)   # read the entire WAV file
                txt += self.speech.recognize_google(
                    audio, key=self.sr_keys['GOOGLE_KEY'])
        except sr.UnknownValueError:
            txt += "Google Speech Recognition could not understand audio"
        except sr.RequestError as exception:
            txt += "Could not request results from " \
                   "Google Speech Recognition service; {0}".format(exception)
        logging.debug("Parsed %s --> %s", fname, txt)
        return txt

    @staticmethod
    def _parse_msg_header(fname):
        """Parse asterisk voicemail metadata."""
        ini = configparser.ConfigParser()
        ini.read(fname)
        try:
            return dict(ini.items('message'))
        except configparser.NoSectionError:
            logging.exception("Couldn't parse: %s", fname)
            return

    @staticmethod
    def _sha256(fname):
        """Get SHA256 sum of a file contents."""
        sha = hashlib.sha256()
        with open(fname, "rb") as infile:
            for chunk in iter(lambda: infile.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def get_mbox_status(self):
        """Parse all messages in a mailbox."""
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
                    data[basename] = {'mbox': subdir}
                if ext == '.txt':
                    data[basename]['info'] = self._parse_msg_header(filename)
                elif ext == '.wav':
                    data[basename]['sha'] = self._sha256(filename)
                    data[basename]['wav'] = filename
        for fname, ref in list(data.items()):
            if ('info' not in ref or 'sha' not in ref or
                    not os.path.isfile(ref['wav'])):
                logging.debug('Message is not complete: ' + fname)
                del data[fname]
                continue
            sha = ref['sha']
            if sha not in self.cache:
                self.cache[sha] = {}
            if 'txt' not in self.cache[sha]:
                self.cache[sha]['txt'] = self._speech_to_text(ref['wav'])
                self._save_cache()
            logging.debug("SHA (%s): %s", fname, sha)
            ref['text'] = self.cache[sha]['txt']
        return data

    def queue(self):
        """Fetch queue object."""
        return self.mbox_queue

    def run(self):
        """Execute main loop."""
        self.mbox_queue.put("rebuild")
        trigger_events = ('IN_DELETE', 'IN_CLOSE_WRITE',
                          'IN_MOVED_FROM', 'IN_MOVED_TO')
        rebuild = False
        try:
            for event in self.inot.event_gen():
                if event is not None:
                    (_header, type_names, _watch_path, _filename) = event
                    if set(type_names) & set(trigger_events):
                        rebuild = True
                else:
                    if rebuild:
                        logging.debug("Rebuilding mailbox due to event: %s",
                                      type_names)
                        self.mbox_queue.put("rebuild")
                    rebuild = False
        finally:
            for subdir in self.subdirs:
                directory = os.path.join(self.path, subdir)
                self.inot.remove_watch(directory.encode('utf-8'))
