"""Monitor cdr logs for changes."""
import os
import sys
import csv
import time
import logging
import posixpath
from threading import Thread
from asterisk_mbox.utils import PollableQueue


class WatchCDR(Thread):
    """Watch for new entries in the CDR database."""

    def __init__(self, cdr_path, sleep=5.0):
        """Initialize variables."""
        Thread.__init__(self)

        self._cdr_queue = PollableQueue()
        self._sleep = sleep
        self._inot = None
        self._watch = None
        self._sql = None
        self._cdr_file = None
        self._entries = []
        self._datefield = 'calldate'
        if not cdr_path:
            # Disable CDR handling
            self._keymap = {}
        elif os.path.isfile(cdr_path):
            self._cdr_file = cdr_path
            self._header = ['accountcode', 'src', 'dst', 'dcontext', 'clid',
                            'channel', 'dstchannel', 'lastapp', 'lastdata',
                            'start', 'answer', 'end', 'duration', 'billsec',
                            'disposition', 'amaflags', 'uniqueid', 'userfield']
            self._keymap = {
                'time': 'start',
                'callerid': 'clid',
                'src': 'src',
                'dest': 'lastdata',
                'context': 'dcontext',
                'application': 'lastapp',
                'duration': 'duration',
                'disposition': 'disposition',
                }
            try:
                if sys.platform.startswith('linux'):
                    import inotify.adapters
                    self._inot = inotify.adapters.Inotify()
                    self._inot.add_watch(self._cdr_file.encode('utf-8'))
            finally:
                pass
        else:
            import sqlalchemy
            try:
                self._sql = sqlalchemy.create_engine(
                    posixpath.dirname(cdr_path))
                self._query = sqlalchemy.text(
                    "SELECT * from {} ORDER BY `{}` DESC"
                    .format(posixpath.basename(cdr_path), self._datefield))
            except sqlalchemy.exc.OperationalError as exception:
                logging.error(exception)
            self._keymap = {
                'time': 'calldate',
                'callerid': 'clid',
                'src': 'src',
                'dest': 'lastdata',
                'context': 'dcontext',
                'application': 'lastapp',
                'duration': 'duration',
                'disposition': 'disposition',
                }
        self._keys = list(self._keymap.keys())

    def _update_entries(self, entries):
        entries = [{key: e.get(origkey, "")
                    for (key, origkey) in self._keymap.items()}
                   for e in entries]
        if (len(entries) == len(self._entries)
                and (not entries or entries[0] == self._entries[0])):
            return False
        self._entries = entries
        return True

    def _read_cdr_from_sql(self):
        result = self._sql.execute(self._query)
        # This isn't thread safe, but since the values should
        # virtually never change, is safe in reality.
        # keys = [str(key) for key in result.keys()]
        entries = [{key: str(value) for (key, value)
                    in row.items()} for row in result]
        return self._update_entries(entries)

    def _read_cdr_file(self):
        with open(self._cdr_file) as filp:
            lines = filp.readlines()
            keys = None
            entries = csv.reader(lines, quotechar='"', delimiter=',',
                                 quoting=csv.QUOTE_ALL,
                                 skipinitialspace=True)
            if entries:
                length = len(entries[0])
                if length < len(self._header):
                    keys = self._header[:length]
                else:
                    keys = self._header
                entries = [dict(zip(keys, e[:len(keys)])) for e in entries]
            return self._update_entries(reversed(entries))

    def _inotify_loop(self):
        updated = False
        trigger_events = ('IN_DELETE', 'IN_CLOSE_WRITE',
                          'IN_MOVED_FROM', 'IN_MOVED_TO')
        try:
            for event in self._inot.event_gen():
                if event is not None:
                    (_header, type_names, _watch_path, _filename) = event
                    if set(type_names) & set(trigger_events):
                        updated = True
                else:
                    if updated:
                        if self._read_cdr_file():
                            logging.debug(
                                "Reloading CDR file due to event: %s",
                                type_names)
                            self._cdr_queue.put("updated")
                    updated = False
        finally:
            self._inot.remove_watch(self._cdr_file.encode('utf-8'))

    def run(self):
        """Thread main loop."""
        if self._inot:
            self._inotify_loop()
            return
        last_mtime = 0
        while True:
            updated = False
            if self._sql:
                updated = self._read_cdr_from_sql()
            elif self._cdr_file:
                mtime = os.path.getmtime(self._cdr_file)
                if last_mtime != mtime:
                    updated = self._read_cdr_file()
                    last_mtime = mtime
            if updated:
                self._cdr_queue.put("updated")
            time.sleep(self._sleep)

    def entries(self):
        """Retrieve current CDR log."""
        return self._entries

    def keys(self):
        """Retrieve CDR entity keys."""
        return self._keys

    def count(self):
        """Retrieve number of current CDR entries."""
        return len(self._entries)

    def queue(self):
        """Fetch queue object."""
        return self._cdr_queue
