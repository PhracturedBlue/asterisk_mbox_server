"""Watch mailbox for new messages."""

import os
import pickle
import logging
import configparser
import hashlib
import glob
import subprocess
import tempfile

from threading import Thread, Lock

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
        self.subdirs = []
        self.speech = sr.Recognizer()
        self.status = {}
        self.cache = {}
        self.lock = Lock()

        if os.path.isfile(stt_file):
            with open(stt_file, 'rb') as infile:
                self.cache = pickle.load(infile)
        self._save_cache()
        self.inot = inotify.adapters.Inotify()
        for subdir in ('INBOX', 'Old', 'Urgent'):
            directory = os.path.join(self.path, subdir)
            if os.path.isdir(directory):
                self.subdirs.append(subdir)
                logging.debug("Watching Directory: %s", directory)
                self.inot.add_watch(directory)
            else:
                logging.debug("Directory %s not found", directory)

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

    def _sha_to_fname(self, sha):
        """Find fname from sha256."""
        for fname in self.status:
            if sha == self.status[fname]['sha']:
                return fname
        return None

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

    def _build_mbox_status(self):
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
        self.status = data

    def delete(self, sha):
        """Delete message from mailbox."""
        # This does introduce a race condition between
        # Asterisk resequencing and us deleting, but there isn't
        # much we can do about it
        self.lock.acquire()
        self._build_mbox_status()
        fname = self._sha_to_fname(sha)
        for fil in glob.glob(fname + ".*"):
            os.unlink(fil)
        dirname = os.path.basename(fname)
        paths = {}
        for fil in glob.iglob(os.path.join(dirname + "msg[0-9]*")):
            base, = os.path.splitext(fil)
            paths[base] = None
        last_idx = 0
        rename = []
        with tempfile.TemporaryDirectory(dir=dirname) as tmp:
            for base in sorted(paths):
                if base != os.path.join(dirname + "msg%04d" % (last_idx)):
                    for fil in glob.glob(base + ".*"):
                        ext = os.path.splitext(fil)[1]
                        newfile = "msg%04d.%s" % (last_idx, ext)
                        logging.info("Renaming '" + fil + "' to '"
                                     + os.path.join(dirname, newfile) + "'")
                        rename.append(newfile)
                        os.link(fil, os.path.join(tempfile, newfile))
            for fil in rename:
                finalname = os.path.join(dirname, fil)
                if os.path.lexists(finalname):
                    os.unlink(finalname)
                os.rename(os.path.join(tmp, fil), finalname)
        self.lock.release()

    def mp3(self, sha):
        """Convert WAV to MP3 using LAME."""
        try:
            fname = self._sha_to_fname(sha)
            if not fname:
                return None
            logging.debug("Requested MP3 for %s ==> %s",
                          sha, fname)
            wav = self.status[fname]['wav']
            process = subprocess.Popen(["lame", "--abr", "24", "-mm",
                                        "-h", "-c",
                                        "--resample", "22.050",
                                        "--quiet", wav, "-"],
                                       stdout=subprocess.PIPE)
            result = process.communicate()[0]
            return result
        except OSError:
            logging.exception("Failed To execute lame")
            return

    def update(self):
        """Rebuild mailbox data."""
        self.lock.acquire()
        self._build_mbox_status()
        self.lock.release()

    def get_mbox_status(self):
        """Return current mbox status."""
        return self.status

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
