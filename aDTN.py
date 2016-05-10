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
    def __init__(self, batch_size, sending_freq, wireless_interface):
        """
        Initialize an aDTN instance and its respective key manager and message store, as well as a sending message pool
        from which the next sending batch gets generated.

        Define aDTNInnerPacket to be the payload of aDTNPacket. Define aDTNPacket to be the payload of Ethernet frames
        of type 0xcafe.

        Start two threads: one handles received messages and the other periodically sends a batch of messages
        every sending_freq seconds, then refills the sending pool if necessary.

        The wireless interface should be previously set to ad-hoc mode and its ESSID should be the same in other devices
        running aDTN.
        :param batch_size: number of packets to transmit at each sending operation
        :param sending_freq: number of seconds between two sending operations
        :param wireless_interface: wireless interface to send and receive packets
        """
        self.batch_size = batch_size
        self.sending_freq = sending_freq
        self.wireless_interface = wireless_interface
        self.km = KeyManager()
        self.ms = MessageStore()
        self.sending_pool = []
        self.prepare_sending_pool()
        self.next_message = 0
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.scheduler.enter(self.sending_freq, 1, self.send)
        bind_layers(aDTNPacket, aDTNInnerPacket)
        bind_layers(Ether, aDTNPacket, type=0xcafe)
        self.run()

    def prepare_sending_pool(self):
        """
        Refill the sending pool with packets if its length drops below the sending batch size. Packets contain
        encrypted messages from the message store. If there are not enough messages to be sent, fake packets are
        generated until the sending pool is full.
        """
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
        """
        Send a batch of randomly selected packets from the sending pool, then ensure the sending pool gets refilled if
        necessary. The packets are encapsulated in an Ethernet frame of type 0xcafe and removed from the sending pool,
        and finally broadcast in a batch.
        This function reschedules itself to occur every sending_freq seconds.
        """
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
        """
        Process a received frame by attempting to decrypt its payload - the aDTN packet - with every key in the key
        store. If a decryption succeeds, the extracted message is stored in the message store, otherwise the next key is
        used. If all decryptions fail, the packet is discarded.
        :param frame: the Ethernet frame containing an aDTN packet
        """
        payload = frame.payload.load
        for key in self.km.keys.values():
            try:
                ap = aDTNPacket(key=key)
                ap.dissect(payload)
                msg = ap.payload.payload.load.decode('utf-8')
                logging.debug("Decrypted with key {}".format(b2s(key)[:6]))
                logging.debug("Received msg: {}".format(msg))
                self.ms.add_message(msg)
            except CryptoError:
                pass

    def run(self):
        """
        Run the aDTN network functionality in two threads, one for sending and the other for receiving. Received
        Ethernet frames are filtered for ethertype and processed if they match the 0xcafe type. The sending thread runs
        a scheduler for periodic sending of aDTN packets.
        """
        t_snd = Thread(target=self.scheduler.run, kwargs={"blocking": True})
        t_rcv = Thread(target=sniff, kwargs={"iface": self.wireless_interface,
                                             "prn": lambda p: self.process(p),
                                             "filter": "ether proto 0xcafe",
                                             "store": 0})
        t_snd.start()
        t_rcv.start()

def parse_args():
    """ Parse command line arguments.
    :return: arguments received via the command line
    """
    parser = ArgumentParser(description='Run an aDTN simulation instance.')
    parser.add_argument('batch_size', type=int, help='how many messages to send in a batch')
    parser.add_argument('sending_freq', type=int, help='interval (in s) between sending a batch')
    parser.add_argument('wireless_interface', type=str, help='name of the wireless interface')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    adtn = aDTN(args.batch_size, args.sending_freq, args.wireless_interface)
