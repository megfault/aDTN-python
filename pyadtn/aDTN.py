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
    '''
    Receives and sends aDTN packets.
    Keys used for encrypting and decrypting the packets are stored in a KeyManager.
    Received payload is stored in a MessageStore instance.
    '''
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
        self.__batch_size = batch_size
        self.__sending_freq = sending_freq
        self.__wireless_interface = wireless_interface
        self.__km = KeyManager()
        self.__ms = DataStore(data_store)
        self.__sending_pool = []
        self.__scheduler = sched.scheduler(time.time, time.sleep)
        self.__scheduled = None
        self.__sniffing = False
        self.__thread_receive = None
        bind_layers(aDTNPacket, aDTNInnerPacket)
        bind_layers(Ether, aDTNPacket, type=0xcafe)

    def __prepare_sending_pool(self):
        """
        Refill the sending pool with packets if its length drops below the sending batch size. Packets contain
        encrypted messages from the message store. If there are not enough messages to be sent, fake packets are
        generated until the sending pool is full.
        """
        if len(self.__sending_pool) < self.__batch_size:
            to_send = self.__ms.get_data()[:self.__batch_size]
            for message in to_send:
                for key in self.__km.keys.values():
                    packet = aDTNPacket(key=key) / aDTNInnerPacket() / message
                    self.__sending_pool.append(packet)
            while len(self.__sending_pool) < self.__batch_size:
                fake_key = self.__km.get_fake_key()
                self.__sending_pool.append((aDTNPacket(key=fake_key) / aDTNInnerPacket()))

    def __send(self):
        """
        Send a batch of randomly selected packets from the sending pool, then ensure the sending pool gets refilled if
        necessary. The packets are encapsulated in an Ethernet frame of type 0xcafe and removed from the sending pool,
        and finally broadcast in a batch.
        This function reschedules itself to occur every sending_freq seconds.
        """
        if self.__scheduled == True:
            self.__scheduler.enter(self.__sending_freq, 1, self.__send)
            batch = []
            s = sample(self.__sending_pool, self.__batch_size)
            for pkt in s:
                batch.append(Ether(dst="ff:ff:ff:ff:ff:ff", type=0xcafe) / pkt)
                self.__sending_pool.remove(pkt)
            sendp(batch, iface=self.__wireless_interface)
            logging.debug("Sent batch")
            self.__prepare_sending_pool()



    def __process(self, frame):
        """
        Process a received frame by attempting to decrypt its payload - the aDTN packet - with every key in the key
        store. If a decryption succeeds, the extracted message is stored in the message store, otherwise the next key is
        used. If all decryptions fail, the packet is discarded.
        :param frame: Ethernet frame containing an aDTN packet
        """
        payload = frame.payload.load
        for key in self.__km.keys.values():
            try:
                ap = aDTNPacket(key=key)
                ap.dissect(payload)
                msg = ap.payload.payload.load.decode('utf-8')
                logging.debug("Decrypted with key {}".format(b2s(key)[:6]))
                logging.debug("Received msg: {}".format(msg))
                self.__ms.add_object(msg)
            except CryptoError:
                pass

    def __sniff(self):
        while True:
            if self.__sniffing is False:
                return
            sniff(iface=self.__wireless_interface, prn=self.__process, filter=FILTER, store=0, timeout=SNIFF_TIMEOUT)

    def start_receiving(self):
        self.__sniffing = True
        self.__thread_receive = Thread(target=self.__sniff)
        self.__thread_receive.start()

    def stop_receiving(self):
        self.__sniffing = False
        self.__thread_receive.join()
        
    def start(self):
        """
        Run the aDTN network functionality in two threads, one for sending and the other for receiving. Received
        Ethernet frames are filtered for ethertype and processed if they match the 0xcafe type. The sending thread runs
        a scheduler for periodic sending of aDTN packets.
        """
        self.__prepare_sending_pool()
        self.__scheduler.enter(self.__sending_freq, 1, self.__send)
        self.__scheduled = True
        self.__thread_send = Thread(target=self.__scheduler.run, kwargs={"blocking": True})
        self.__thread_send.start()
        self.start_receiving()

    def stop(self):
        """
        Stop aDTN. Make sure the two threads created at start are finished properly.
        """
        self.__scheduled = False
        try:
            while not self.__scheduler.empty():
                event = self.__scheduler.queue.pop()
                self.__scheduler.cancel(event)
        except ValueError: # In case the popped event started running in the meantime...
            self.stop() # ...call the stop function once more.
        # By now the scheduler has run empty and so the sending thread has stopped.
        # Now we just have to join the receiving thread to stop aDTN completely:
        self.stop_receiving()


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
