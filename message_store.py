from tinydb import TinyDB, Query
from tinydb.operations import increment
from nacl.hash import sha256
from nacl.encoding import HexEncoder
import time
from threading import RLock

from settings import DEFAULT_DIR, DATABASE_FN
from utils import log


class MessageStore():
    def __init__(self, size_threshold=None):
        self.size_threshold = size_threshold
        self.message_count = 0
        self.db = TinyDB(DEFAULT_DIR + DATABASE_FN)
        self.db.purge()
        self.stats = self.db.table('stats')
        self.messages = self.db.table('messages')
        self.lock = RLock()

    def create_new_message(self, message, hash, time):
        self.messages.insert({'hash': hash, 'content': message})
        self.stats.insert({'hash': hash,
                           'first_seen': time,
                           'receive_count': 0,
                           'send_count': 0,
                           'last_received': None,
                           'last_sent': None,
                           'deleted': False})

    def add_message(self, message):
        bytes = message.encode('utf-8')
        h = sha256(bytes, HexEncoder)
        idx = h.decode('utf-8')
        with self.lock:
            Stats = Query()
            res = self.stats.search(Stats.hash == idx)
            now = int(time.time())
            if len(res) == 0:
                self.create_new_message(message, idx, now)
                log("message inserted: {}".format(message))
                self.message_count += 1
            else:
                self.stats.update({'last_received': now}, 'hash' == idx)
                self.stats.update(increment('receive_count'), 'hash' == idx)

    def get_messages(self, count=1):
        with self.lock:
            stats = self.stats.all()
            res = sorted(stats, key=lambda x: (x['receive_count'], x['send_count'], x['last_sent']))[:10]
            now = int(time.time())
            messages = []
            for r in res:
                idx = r['hash']
                Messages = Query()
                msg = self.messages.search(Messages.hash == idx)[0]
                messages.append(msg)
                self.stats.update({'last_sent': now}, 'hash' == idx)
                self.stats.update(increment('send_count'), 'hash' == idx)
        return messages
