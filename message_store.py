from tinydb import TinyDB, Query
from tinydb.operations import increment
import time
from threading import RLock
from argparse import ArgumentParser


from settings import DEFAULT_DIR, DATABASE_FN
from utils import log, hash_string


class MessageStore():
    def __init__(self, size_threshold=None):
        self.size_threshold = size_threshold
        self.db = TinyDB(DEFAULT_DIR + DATABASE_FN)
        self.stats = self.db.table('stats')
        self.messages = self.db.table('messages')
        self.lock = RLock()

    def create_new_message(self, message, hash, time):
        self.messages.insert({'idx': hash, 'content': message})
        self.stats.insert({'idx': hash,
                           'first_seen': time,
                           'receive_count': 0,
                           'send_count': 0,
                           'last_received': None,
                           'last_sent': None,
                           'deleted': False})

    def add_message(self, message):
        idx = hash_string(message)
        now = int(time.time())
        with self.lock:
            Stats = Query()
            res = self.stats.search(Stats.idx == idx)
            if len(res) == 0:
                self.create_new_message(message, idx, now)
                log("message inserted: {}".format(message))
            else:
                deleted = res[0]['deleted']
                if deleted:
                    log("Received deleted message: {}".format(message))
                else:
                    self.stats.update({'last_received': now}, Stats.idx == idx)
                    self.stats.update(increment('receive_count'), Stats.idx == idx)

    def get_messages(self, count=1):
        with self.lock:
            Stats = Query()
            stats = self.stats.search(Stats.deleted == False)
            res = sorted(stats, key=lambda x: (x['receive_count'], x['send_count'], x['last_sent']))[:10]
            now = int(time.time())
            messages = []
            for r in res:
                idx = r['idx']
                Messages = Query()
                msg = self.messages.search(Messages.idx == idx)[0]['content']
                messages.append(msg)
                self.stats.update({'last_sent': now}, Messages.idx == idx)
                self.stats.update(increment('send_count'), Messages.idx == idx)
        return messages

    def delete_message(self, msg_id):
        with self.lock:
            Stats = Query()
            Message = Query()
            res = self.stats.search(Stats.idx == msg_id)
            self.stats.update({'deleted': True}, Stats.idx == msg_id)
            record = self.messages.get(Message.idx == msg_id)
            if record is not None:
                self.messages.remove(eids=[record.eid])
            else:
                log("No message to delete: {}".format(msg_id))

    def print_messages(self):
        msgs = ms.messages.all()
        for msg in msgs:
            print("{}\t{}".format(msg['idx'], msg['content']))

    def wipe(self):
        self.stats.purge()
        self.messages.purge()
        self.db.purge()


if __name__ == '__main__':
    parser = ArgumentParser(description='Manage aDTN messages')
    parser.add_argument('-c', metavar="message", type=str, dest="message", default=None, help='create a message and add it to the message store for later sending')
    parser.add_argument('-a', '--all', action="store_true", help='display all messages')
    parser.add_argument('-w', '--wipe', action="store_true", help='wipe all messages and stats')
    parser.add_argument('-d', metavar="message_id", type=str, dest="to_delete", default=None, help='delete message with id <message_id>')
    args = parser.parse_args()

    ms = MessageStore()

    if args.message is not None:
        ms.add_message(args.message)

    if args.to_delete is not None:
        ms.delete_message(args.to_delete)

    if args.all:
        ms.print_messages()

    if args.wipe:
        ms.wipe()
