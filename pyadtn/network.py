from socket import socket, AF_PACKET, SOCK_RAW
from pyadtn.utils import build_frame
from construct import Struct, Bytes, Enum
import asyncio
import uvloop


# frame structure:
# 6 bytes dst mac addr
# 6 bytes src mac addr
# 2 bytes ethertype (0xcafe, 0xbeef)
# 1482 payload
# 4 bytes checksum (IEEE's CRC)


WIFACE = "wlp3s0"
PAYLOAD_LEN = 1500 - 8
BCAST_ADDR = "\xff\xff\xff\xff\xff\xff"
ETHERTYPE = b'cafe'


class Network():
    def __init__(self, wireless_interface):
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self._socket = socket(AF_PACKET, SOCK_RAW)
        self._socket.bind((wireless_interface, 0))
        # TODO some thing with asyncio and select

    def send(self, frame):
        self._socket.send(frame)


    def receive(self):
        data, addr = self._socket.recvfrom(1500)
        return data