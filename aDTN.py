from nacl.exceptions import CryptoError
from scapy.all import Ether, sendp, sniff, bind_layers
import time
import sched
from threading import Thread
import random
import argparse
import logging

from message_store import MessageStore
from key_manager import KeyManager
from aDTN_packet import aDTNPacket, aDTNInnerPacket
from utils import b2s




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
