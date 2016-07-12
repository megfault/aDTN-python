from nacl.exceptions import CryptoError
from scapy.all import Ether, sendp, sniff, bind_layers
import time
import sched
from threading import Thread
from argparse import ArgumentParser
from random import sample
import logging
from atexit import register

from pyadtn.message_store import DataStore
from pyadtn.key_manager import KeyManager
from pyadtn.aDTN_packet import aDTNPacket, aDTNInnerPacket
from pyadtn.utils import b2s

FILTER = "ether proto 0xcafe"
SNIFF_TIMEOUT = 5


class aDTN():
    """
    Receives and sends aDTN packets.
    Keys used for encrypting and decrypting the packets are stored in a KeyManager.
    Received payload is stored in a MessageStore instance.
    """
    def __init__(self, batch_size, sending_freq, wireless_interface, data_store):
        """
        Initialize an aDTN instance and its respective key manager and message store, as well as a sending message pool
        from which the next sending batch gets generated.

        Define aDTNInnerPacket to be the payload of aDTNPacket. Define aDTNPacket to be the payload of Ethernet frames
        of type 0xcafe.

        Set up a scheduler to handle message sending.
        Define a thread to handle received messages.

        The wireless interface should be previously set to ad-hoc mode and its ESSID should be the same in other devices
        running aDTN.
        :param batch_size: number of packets to transmit at each sending operation
        :param sending_freq: number of seconds between two sending operations
        :param wireless_interface: wireless interface to send and receive packets
        """
        self._batch_size = batch_size
        self._sending_freq = sending_freq
        self._wireless_interface = wireless_interface
        self._km = KeyManager()
        self.data_store = DataStore(data_store)
        self._sending_pool = []
        self._scheduler = sched.scheduler(time.time, time.sleep)
        self._sending = None
        self._sniffing = None
        self._thread_send = None
        self._thread_receive = None
        bind_layers(aDTNPacket, aDTNInnerPacket)
        bind_layers(Ether, aDTNPacket, type=0xcafe)

    def _prepare_sending_pool(self):
        """
        Refill the sending pool with packets if its length drops below the sending batch size. Packets contain
        encrypted messages from the message store. If there are not enough messages to be sent, fake packets are
        generated until the sending pool is full.
        """
        if len(self._sending_pool) < self._batch_size:
            to_send = self.data_store.get_data()[:self._batch_size]
            for message in to_send:
                for key in self._km.keys.values():
                    packet = aDTNPacket(key=key) / aDTNInnerPacket() / message
                    self._sending_pool.append(packet)
            while len(self._sending_pool) < self._batch_size:
                fake_key = self._km.get_fake_key()
                self._sending_pool.append((aDTNPacket(key=fake_key) / aDTNInnerPacket()))

    def _send(self):
        """
        Send a batch of randomly selected packets from the sending pool, then ensure the sending pool gets refilled if
        necessary. The packets are encapsulated in an Ethernet frame of type 0xcafe and removed from the sending pool,
        and finally broadcast in a batch.
        This function reschedules itself to occur every sending_freq seconds.
        """
        self._scheduler.enter(self._sending_freq, 1, self._send)
        if self._sending:
            batch = []
            s = sample(self._sending_pool, self._batch_size)
            for pkt in s:
                batch.append(Ether(dst="ff:ff:ff:ff:ff:ff", type=0xcafe) / pkt)
                self._sending_pool.remove(pkt)
            sendp(batch, iface=self._wireless_interface)
            logging.debug("Sent batch")
            self._prepare_sending_pool()

    def _process(self, frame):
        """
        Process a received frame by attempting to decrypt its payload - the aDTN packet - with every key in the key
        store. If a decryption succeeds, the extracted message is stored in the message store, otherwise the next key is
        used. If all decryptions fail, the packet is discarded.
        :param frame: Ethernet frame containing an aDTN packet
        """
        payload = frame.payload.load
        for key in self._km.keys.values():
            try:
                ap = aDTNPacket(key=key)
                ap.dissect(payload)
                msg = ap.payload.payload.load.decode('utf-8')
                logging.debug("Decrypted with key {}".format(b2s(key)[:6]))
                logging.debug("Received msg: {}".format(msg))
                self.data_store.add_object(msg)
            except CryptoError:
                pass

    def _sniff(self):
        """ Wrapper for packet sniffing. """
        while True:
            if self._sniffing is False:
                return
            sniff(iface=self._wireless_interface, prn=self._process, filter=FILTER, store=0, timeout=SNIFF_TIMEOUT)

    def start(self):
        """
        Run the aDTN network functionality in two threads, one for sending and the other for receiving. Received
        Ethernet frames are filtered for ethertype and processed if they match the 0xcafe type. The sending thread runs
        a scheduler for periodic sending of aDTN packets.
        """
        self._prepare_sending_pool()
        self._scheduler.enter(self._sending_freq, 1, self._send)
        self._sending = True
        self._thread_send = Thread(target=self._scheduler.run, kwargs={"blocking": True})
        self._thread_send.start()
        self._sniffing = True
        self._thread_receive = Thread(target=self._sniff)
        self._thread_receive.start()

    def stop(self):
        """
        Stop aDTN. Make sure the two threads created at start are finished properly.
        """
        self._sending = False
        try:
            while not self._scheduler.empty():
                event = self._scheduler.queue.pop()
                self._scheduler.cancel(event)
        except ValueError:  # In case the popped event started running in the meantime...
            self.stop()  # ...call the stop function once more.
        # By now the scheduler has run empty, so join the thread:
        self._thread_send.join()
        # Now we just have to join the receiving thread to stop aDTN completely:
        self._sniffing = False
        self._thread_receive.join()


def parse_args():
    """ Parse command line arguments.
    :return: arguments received via the command line
    """
    parser = ArgumentParser(description='Run an aDTN simulation instance.')
    parser.add_argument('batch_size', type=int, help='how many messages to send in a batch')
    parser.add_argument('sending_freq', type=int, help='interval (in s) between sending a batch')
    parser.add_argument('wireless_interface', type=str, help='name of the wireless interface')
    parser.add_argument('data_store', type=str, default=None, help="file storing the data objects")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    adtn = aDTN(args.batch_size, args.sending_freq, args.wireless_interface, args.data_store)
    register(aDTN.stop, adtn)
    adtn.start()
