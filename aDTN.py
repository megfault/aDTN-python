from nacl.secret import *
from nacl.utils import random as rand
import nacl.hash
import nacl.encoding
from nacl.exceptions import CryptoError
from pathlib import Path
import binascii
from scapy.all import Ether, Packet, LenField, sendp, sniff, bind_layers
import sqlite3
import time
import sched
from threading import RLock, Thread
import random
import argparse
import logging

DEFAULT_DIR = "data/"
KEYS_DIR = "keys/"
DATABASE_FN = "messagestore.db"
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
                    pkt = (aDTNPacket(key=key) / aDTNInnerPacket() / message)
                    self.sending_pool.append(pkt)
                    logging.debug("Encrypted using key {}.".format(binascii.hexlify(key).decode('utf-8')))
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
        self.prepare_sending_pool()

    def process(self, aDTN_packet):
        for key in self.km.keys.values():
            logging.debug("Attempting to decrypt with key {}.".format(binascii.hexlify(key).decode('utf8')))
            try:
                ap = aDTNPacket(key=key)
                ap.dissect(aDTN_packet.build())
                self.ms.add_message(ap.payload.payload)
                logging.debug("Decrypted.")
                return
            except CryptoError:
                logging.debug("Unable to decrypt.")

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
        t_rcv.run()
        t_snd.run()


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
                hx = binascii.hexlify(key)
                s = hx.decode('utf-8')
                with file_path.open('w', encoding='utf-8') as f:
                    f.write(s)

    def load_keys(self, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        for file_path in path.iterdir():
            if file_path.suffix == ".key":
                with file_path.open('r', encoding='utf-8') as f:
                    s = f.readline()
                hx = s.encode('utf-8')
                key = binascii.unhexlify(hx)
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
        if self.auto_encrypt and self.key:
            return encrypt(pay, self.key)
        return pay

    # TODO misuse of method, find the right one
    def extract_padding(self, s):
        if self.auto_encrypt and self.key:
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
        conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM stats;")
        cursor.execute("DELETE FROM message;")
        conn.commit()
        conn.close()
        self.lock = RLock()

    def add_message(self, message):
        bytes = message.encode('utf-8')
        h = nacl.hash.sha256(bytes, nacl.encoding.HexEncoder)
        idx = h.decode('utf-8')
        with self.lock:
            conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM stats WHERE hash=?;", [idx])
            res = cursor.fetchall()
            now = int(time.time())
            if len(res) == 0:
                # new message
                cursor.execute("INSERT INTO stats VALUES (?, ?, ?, ?, ?, ?, ?)", [idx, now, None, None, 0, 0, None])
                cursor.execute("INSERT INTO message VALUES (?, ?)", [idx, message])
                logging.debug("message inserted: {}".format(message))
                self.message_count += 1
            else:
                h, first_seen, last_rcv, last_sent, rcv_ct, snd_ct = res[0]
                cursor.execute("UPDATE stats SET last_rcv=?, snd_ct=? WHERE hash=?", [now, rcv_ct + 1, idx])
            if self.size_threshold is not None and self.message_count > self.size_threshold:
                self.purge(10)
            conn.commit()
            conn.close()

    def purge(self, count):
        with self.lock:
            conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
            cursor = conn.cursor()
            cursor.execute("SELECT hash FROM stats ORDER BY rcv_ct DESC, snd_ct DESC, last_rcv DESC")
            res = cursor.fetchmany(count)
            now = int(time.time())
            for r in res:
                idx = r[0]
                cursor.execute("DELETE FROM message WHERE hash=?", [idx])
                cursor.execute("UPDATE stats SET deleted=? WHERE hash=?", [now, idx])
            conn.commit()
            conn.close()

    def get_messages(self, count=1):
        with self.lock:
            conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
            cursor = conn.cursor()
            cursor.execute("SELECT hash FROM stats ORDER BY rcv_ct ASC, snd_ct ASC, last_snt ASC")
            res = cursor.fetchmany(count)
            now = int(time.time())
            messages = []
            for r in res:
                idx = r[0]
                cursor.execute("SELECT content FROM message WHERE hash=?", [idx])
                msg = cursor.fetchone()[0]
                messages.append(msg)
                cursor.execute("SELECT snd_ct FROM stats WHERE hash=?", [idx])
                snd_ct = cursor.fetchone()[0]
                cursor.execute("UPDATE stats SET last_snt=?, snd_ct=? WHERE hash=?", [now, snd_ct + 1, idx])
            conn.commit()
            conn.close()
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
