from tinydb import TinyDB, Query
from tinydb.operations import increment
import time
from threading import RLock
from argparse import ArgumentParser

from pyadtn.settings import DEFAULT_DIR, DEFAULT_DATABASE_FN
from pyadtn.utils import hash_string

from logging import basicConfig, debug, DEBUG
basicConfig(filename='message_store.log', level=DEBUG,
            format='[%(relativeCreated)8d] %(message)s', )


class DataStore:
    """
    Network layer storage for payload received and sent by aDTN.
    Payload retrieved from the datastore are chosen according to a fairness heuristic in order to give least
    popular objects in the network a chance to spread.
    """
    def __init__(self, db_default_dir=DEFAULT_DIR, db_filename=DEFAULT_DATABASE_FN, size_threshold=None):
        """
        Initialize data store.
        :param size_threshold: maximum storage size, in number of data objects
        :param db_filename: name of the file where the data is stored
        """
        self.size_threshold = size_threshold
        self.db = TinyDB(db_default_dir + db_filename)
        self.stats = self.db.table('stats')
        self.data = self.db.table('messages')
        self.lock = RLock()

    def add_object(self, data):
        """
        Attempt to insert a data object into the store. If it does not exist, it gets initialized. Otherwise the
        statistics are updated by increasing the receive count and the time of the last reception if the message has
        not been flagged as deleted.
        :param data: data object to store
        """
        idx = hash_string(data)
        now = int(time.time())
        with self.lock:
            Stats = Query()
            res = self.stats.search(Stats.idx == idx)
            if len(res) == 0:
                self.data.insert({'idx': idx, 'content': data})
                self.stats.insert({'idx': idx,
                                   'first_seen': now,
                                   'receive_count': 0,
                                   'send_count': 0,
                                   'last_received': None,
                                   'last_sent': None,
                                   'deleted': False})
                debug("Data object created: {}".format(data))
            else:
                deleted = res[0]['deleted']
                if deleted:
                    debug("Received deleted data object: {}".format(data))
                self.stats.update({'last_received': now}, Stats.idx == idx)
                self.stats.update(increment('receive_count'), Stats.idx == idx)
                debug("Data object updated: {}".format(data))

    def get_data(self):
        """
        Retrieve the data objects sorted by increasing popularity, namely in increasing receive_count, then send_count
        and finally the last time they were sent by the current aDTN node.
        :return: data objects sorted by increasing popularity.
        """
        with self.lock:
            Stats = Query()
            stats = self.stats.search(Stats.deleted == False)
            res = sorted(stats, key=lambda x: (x['receive_count'], x['send_count'], x['last_sent']))[:10]
            now = int(time.time())
            objects = []
            for r in res:
                idx = r['idx']
                Objects = Query()
                obj = self.data.search(Objects.idx == idx)[0]['content']
                objects.append(obj)
                self.stats.update({'last_sent': now}, Objects.idx == idx)
                self.stats.update(increment('send_count'), Objects.idx == idx)
        return objects

    def delete_data(self, object_id):
        """
        Delete a data object given its ID.
        :param object_id: ID of the data object to delete.
        """
        with self.lock:
            Stats = Query()
            Message = Query()
            res = self.stats.search(Stats.idx == object_id)
            self.stats.update({'deleted': True}, Stats.idx == object_id)
            record = self.data.get(Message.idx == object_id)
            if record is not None:
                self.data.remove(eids=[record.eid])
                debug("Deleted message: {}".format(object_id))
            else:
                debug("No data to delete: {}".format(object_id))

    def list_objects(self):
        """
        Print a list of data objects preceded by its object ID.
        """
        with self.lock:
            objects = ms.data.all()
            for obj in objects:
                print("{}\t{}".format(obj['idx'], obj['content']))

    def wipe(self):
        """
        Empty the data store.
        """
        with self.lock:
            self.stats.purge()
            self.data.purge()
            self.db.purge()

def parse_args():
    parser = ArgumentParser(description='Manage aDTN messages')
    parser.add_argument('data_store', type=str, default=None, help="file storing the data objects")
    parser.add_argument('-c', metavar="data", type=str, dest="data", default=None, help='create a data object and add it to the data store for later sending')
    parser.add_argument('-a', '--all', action="store_true", help='display all data objects')
    parser.add_argument('-w', '--wipe', action="store_true", help='wipe all data objects and stats')
    parser.add_argument('-d', metavar="object_id", type=str, dest="to_delete", default=None, help='delete data object with id <object_id>')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()

    ms = DataStore(args.data_store)

    if args.data is not None:
        ms.add_object(args.data)
    if args.to_delete is not None:
        ms.delete_data(args.to_delete)
    if args.all:
        ms.list_objects()
    if args.wipe:
        ms.wipe()
