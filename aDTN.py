from nacl.exceptions import CryptoError
from scapy.all import Ether, sendp, sniff, bind_layers
import time
import sched
from threading import Thread
from argparse import ArgumentParser
from random import sample
import logging

from message_store import MessageStore
from key_manager import KeyManager
from aDTN_packet import aDTNPacket, aDTNInnerPacket
from utils import b2s


class aDTN():
    '''
    Receives and sends aDTN packets.
    Keys used for encrypting and decrypting the packets are stored in a KeyManager.
    Received payload is stored in a MessageStore instance.
    '''
    def __init__(self, batch_size, sending_freq, wireless_interface, data_store):
        self.batch_size = batch_size
        self.sending_freq = sending_freq
        self.wireless_interface = wireless_interface
        self.km = KeyManager()
        self.ms = MessageStore(data_store)
        self.sending_pool = []
        self.prepare_sending_pool()
        self.next_message = 0
        self.scheduler = sched.scheduler(time.time, time.sleep)
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
        s = sample(self.sending_pool, self.batch_size)
        for pkt in s:
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

    def run(self):
        t_snd = Thread(target=self.scheduler.run, kwargs={"blocking": True})
        t_rcv = Thread(target=sniff, kwargs={"iface": self.wireless_interface,
                                             "prn": lambda p: self.process(p),
                                             "filter": "ether proto 0xcafe",
                                             "store": 0})
        t_snd.start()
        t_rcv.start()

def parse_args():
    parser = ArgumentParser(description='Run an aDTN simulation instance.')
    parser.add_argument('batch_size', type=int, help='how many messages to send in a batch')
    parser.add_argument('sending_freq', type=int, help='interval (in s) between sending a batch')
    parser.add_argument('wireless_interface', type=str, help='name of the wireless interface')
    parser.add_argument('data_store', type=str, help='filename of database for network messages')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    bind_layers(aDTNPacket, aDTNInnerPacket)
    bind_layers(Ether, aDTNPacket, type=0xcafe)
    adtn = aDTN(args.batch_size, args.sending_freq, args.wireless_interface,
                args.data_store)
    adtn.run()
