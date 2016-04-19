from nacl.secret import *
from nacl.utils import random as rand
import nacl.hash
import nacl.encoding
from nacl.exceptions import CryptoError
from pathlib import Path
import binascii
from scapy.all import Ether, Packet, LenField, sendp, sniff, bind_layers
from tinydb import TinyDB, Query
from tinydb.operations import increment
import time
import sched
from threading import RLock, Thread
import random
import argparse
import logging

DEFAULT_DIR = "data/"
KEYS_DIR = "keys/"
DATABASE_FN = "messagestore.json"
PACKET_SIZE = 1500
MAX_INNER_SIZE = 1466

logging.basicConfig(filename='aDTN.log', level=logging.DEBUG,
                    format='[%(relativeCreated)8d] %(message)s',
                    )

def generate_iv():
    return rand(SecretBox.NONCE_SIZE)


def encrypt(message, key, nonce_generator=generate_iv):
    return SecretBox(key).encrypt(message, nonce_generator())


def decrypt(encrypted, key):
    return SecretBox(key).decrypt(encrypted)


def b2s(b):
    return binascii.hexlify(b).decode('utf-8')

def s2b(s):
    return binascii.unhexlify(s.encode('utf-8'))

class aDTN():
    def __init__(self, batch_size, sending_freq, creation_rate, name, wireless_interface):
        self.batch_size = batch_size
        self.sending_freq = sending_freq
        self.creation_rate = creation_rate
        self.device_name = name
        self.wireless_interface = wireless_interface
        self.km = KeyManager()
        self.ms = MessageStore()
        self.sending_pool = []
        self.prepare_sending_pool()
        self.next_message = 0
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.scheduler.enter(self.writing_interval(), 2, self.write_message)
        self.scheduler.enter(self.sending_freq, 1, self.send)

    def prepare_sending_pool(self):
        if len(self.sending_pool) < self.batch_size:
            to_send = self.ms.get_messages(count=self.batch_size)
            for message in to_send:
                for key in self.km.keys.values():
                    pkt = aDTNPacket(key=key) / aDTNInnerPacket() / message
                    self.sending_pool.append(pkt)
            while len(self.sending_pool) < self.batch_size:
                fake_key = self.km.get_fake_key()
                self.sending_pool.append((aDTNPacket(key=fake_key) / aDTNInnerPacket()))

    def send(self):
        self.scheduler.enter(self.sending_freq, 1, self.send)
        batch = []
        sample = random.sample(self.sending_pool, self.batch_size)
        for pkt in sample:
            batch.append(Ether(dst="ff:ff:ff:ff:ff:ff", type=0xcafe) / pkt)
            self.sending_pool.remove(pkt)
        sendp(batch, iface=self.wireless_interface)
        logging.debug("Sent batch")
        self.prepare_sending_pool()

    def process(self, frame):
        payload = frame.payload.load
        for key in self.km.keys.values():
            try:
                ap = aDTNPacket(key=key)
                ap.dissect(payload)
                msg = ap.payload.payload.load.decode('utf-8')
                logging.debug("Decrypted with key {}".format(b2s(key)[:6]))
                logging.debug("Received msg: {}".format(msg))
                self.ms.add_message(msg)
                return
            except CryptoError:
                pass
    def writing_interval(self):
        return abs(random.gauss(self.creation_rate, self.creation_rate / 4))

    def write_message(self):
        self.scheduler.enter(self.writing_interval(), 2, self.write_message)
        self.ms.add_message(self.device_name + str(self.next_message))
        self.next_message += 1

    def run(self):
        t_snd = Thread(target=self.scheduler.run, kwargs={"blocking": True})
        t_rcv = Thread(target=sniff, kwargs={"iface": self.wireless_interface,
                                             "prn": lambda p: self.process(p),
                                             "filter": "ether proto 0xcafe"})
        t_snd.start()
        t_rcv.start()


class KeyManager():
    def __init__(self):
        self.keys = dict()
        self.load_keys()

    def __del__(self):
        self.save_keys()

    def create_key(self, key_id=None):
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        if not key_id:
            h = nacl.hash.sha256(key, nacl.encoding.HexEncoder)
            key_id = h.decode('utf-8')[:16]
        self.keys[key_id] = key
        return key_id

    def get_fake_key(self):
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    def save_keys(self, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        for key_id in self.keys:
            file_path = path.joinpath(key_id + ".key")
            if not file_path.exists():
                key = self.keys[key_id]
                s = b2s(key)
                with file_path.open('w', encoding='utf-8') as f:
                    f.write(s)

    def load_keys(self, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        for file_path in path.iterdir():
            if file_path.suffix == ".key":
                with file_path.open('r', encoding='utf-8') as f:
                    s = f.readline()
                key = s2b(s)
                self.keys[file_path.stem] = key


class aDTNPacket(Packet):
    def __init__(self, *args, key=None, nonce=None, auto_encrypt=True, **kwargs):
        self.key = key
        self.auto_encrypt = auto_encrypt
        super().__init__(*args, **kwargs)

    def encrypt(self):
        key = self.key
        byteval = self.payload.build()  # better way to do it?
        encrypted = encrypt(byteval, key)
        self.remove_payload()
        # add_payload will try to figure out the type
        self.add_payload(bytes(encrypted))

    def decrypt(self):
        key = self.key
        byteval = self.payload.load
        decrypted = decrypt(byteval, key)
        self.remove_payload()
        # add_payload will try to figure out the type
        # encrypted is of Type nacl.secret.EncryptedMessage
        self.add_payload(aDTNInnerPacket(decrypted))

    # TODO delegate to encrypt/decrypt after building
    # TODO also breaks show2 and other methods where build is called twice
    def post_build(self, pkt, pay):
        if self.auto_encrypt and self.key is not None:
            return encrypt(pay, self.key)
        return pay

    # TODO misuse of method, find the right one
    def extract_padding(self, s):
        if self.auto_encrypt and self.key is not None:
            return decrypt(s, self.key), None
        return s

    def clone_attrs(self, clone):
        # TODO clone all keys
        clone.key = self.key
        clone.auto_encrypt = self.auto_encrypt
        return clone

    # TODO how to avoid such redundancy
    # scapy seems to have a oop structure problem
    def clone_with(self, payload=None, **kargs):
        pkt = super().clone_with(payload, **kargs)
        return self.clone_attrs(pkt)

    def copy(self):
        pkt = super().copy()
        return self.clone_attrs(pkt)


class aDTNInnerPacket(Packet):
    packet_len = 1460  # TODO get it from layer above, conf.padding_layer
    fields_desc = [LenField("len", default=None)]
    # TODO configure payload type as EncryptedMessage

    def post_build(self, pkt, pay):
        # add padding, will be calculated when calling show2
        # which basically builds and dissects the same packet
        pad_len = self.packet_len - len(pkt) - len(pay)
        # TODO check while adding payload
        if pad_len < 0:
            raise ValueError("Payload in inner packet too big")
        return pkt + pay + b'0' * pad_len

    def extract_padding(self, s):
        l = self.len
        if l > self.packet_len:
            raise ValueError("Payload in inner packet too big")
        return s[:l], s[l:]


class MessageStore():
    def __init__(self, size_threshold=None):
        self.size_threshold = size_threshold
        self.message_count = 0
        self.db = TinyDB(DEFAULT_DIR + DATABASE_FN)
        self.db.purge()
        self.stats = self.db.table('stats')
        self.messages = self.db.table('messages')
        self.lock = RLock()

    def add_message(self, message):
        bytes = message.encode('utf-8')
        h = nacl.hash.sha256(bytes, nacl.encoding.HexEncoder)
        idx = h.decode('utf-8')
        with self.lock:
            Stats = Query()
            res = self.stats.search(Stats.hash == idx)
            now = int(time.time())
            if len(res) == 0:
                # new message
                self.stats.insert({'hash': idx,
                                   'first_seen': now,
                                   'receive_count': 0,
                                   'send_count': 0,
                                   'last_received': None,
                                   'last_sent': None,
                                   'deleted': False})
                self.messages.insert({'hash': idx, 'content': message})
                logging.debug("message inserted: {}".format(message))
                self.message_count += 1
            else:
                # message already in database
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an aDTN simulation instance.')
    parser.add_argument('batch_size', type=int, help='how many messages to send in a batch')  # 10
    parser.add_argument('sending_freq', type=int, help='interval (in s) between sending a batch')  # 30
    parser.add_argument('creation_rate', type=int, help='avg interval between creating a new message')  # 4*3600 = 14400
    parser.add_argument('device_name', type=str, help='name of this device')  # maxwell
    parser.add_argument('wireless_interface', type=str, help='name of the wireless interface')
    args = parser.parse_args()

    bind_layers(aDTNPacket, aDTNInnerPacket)
    bind_layers(Ether, aDTNPacket, type=0xcafe)
    adtn = aDTN(args.batch_size, args.sending_freq, args.creation_rate, args.device_name, args.wireless_interface)
    adtn.run()
