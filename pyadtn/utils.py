from binascii import hexlify, unhexlify, crc32
from nacl.utils import random as rand
from nacl.secret import SecretBox
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from random import randint
from pyric.pyw import macget, getcard
import fcntl, socket, struct
from logging import basicConfig, DEBUG, INFO, FileHandler, Formatter, getLogger
from threading import RLock


basicConfig(filename='debug.log', level=DEBUG,
            format='[%(created)f] %(threadName)s (%(thread)d) -- %(message)s', )
network_fh = FileHandler('network_events.log')
network_fh.setLevel(INFO)
formatter = Formatter('[%(created)f] %(message)s')
network_fh.setFormatter(formatter)
getLogger('').addHandler(network_fh)
lock = RLock()

def log_network(x):
    with lock:
        getLogger('').info(x)


def log_debug(x):
    with lock:
        getLogger('').debug(x)


def encrypt(plaintext, key):
    """
    Encrypt a bytestring with the given key using the Salsa20 algorithm.
    Encryption uses a new nonce by default, but can be overridden in case one needs a custom nonce.
    :param plaintext: bytestring to encrypt
    :param key: a 32 byte long bytestring
    :return: bytestring containing the ciphertext
    """
    nonce = rand(SecretBox.NONCE_SIZE)
    return SecretBox(key).encrypt(plaintext, nonce)


def decrypt(ciphertext, key):
    """
    Decrypt a bytestring with the given key.
    :param ciphertext: a bytestring to decrypt
    :param key: a 32 byte long bytestring
    :return: resulting plaintext
    """
    sb = SecretBox(key)
    return sb.decrypt(ciphertext)


def hash_string(s):
    """
    Hash the input string and convert the result to string format.
    :param s: a string to hash
    :return: hash of the input string in string format.
    """
    b = s.encode('utf-8')
    h = sha256(b, HexEncoder)
    return h.decode('utf-8')


def b2s(b):
    """
    Convert a bytestring to a string.
    :param b: bytestring to convert.
    :return: decoded bytestring in string format.
    """
    return hexlify(b).decode('utf-8')


def s2b(s):
    """
    Convert a string to a bytestring.
    :param s: string to convert
    :return: bytestring conversion of the input string.
    """
    return unhexlify(s.encode('utf-8'))


def hex_string_to_bytes(s):
    """
    Convert a string of hexadecimal characters to a byte string.
    :param s: string of hexadecimal characters
    :return: byte string representation of the input string
    """
    return b''.join(c.encode('utf-8') for c in s)


def mac_address_to_bytes(mac_address):
    """
    Convert a MAC address string (e.g. 00:11:22:33:44:55) to a bytestring (e.g. b'001122334455').
    :param mac_address string representing a MAC address in its usual colon-separated format
    :return: byte string representation of the input macaddress
    """
    mac_digits = "".join(mac_address.split(":"))
    return hex_string_to_bytes(mac_digits)


def real_mac_address(interface):
    """
    Find the MAC address of the given network interface.
    :param interface: network interace name as a string
    :return: string representation of the corresponding MAC address in its usual colon-separated format
    """
    return macget(getcard(interface))


def random_mac_address():
    """
    Generate a random MAC address
    :return: string containing a random MAC address
    """
    def generate_n_hexdigit_pairs(n):
        for _ in range(n):
            s = hex(randint(0, 255))[2:]
            if len(s) == 1:
                s = "0" + s
            yield s
    return ":".join(generate_n_hexdigit_pairs(6))


def calculate_fcs(bytestring):
    fcs = crc32(bytestring)
    return fcs


def build_frame(dst_address, src_address, payload):
    """
    Builds a 1500 byte long Ethernet frame with the given fields and payload, which must be 1482 bytes long.
    :param dst_address string containing destination mac address in its usual format
    :param src_address string containing source mac address, in its usual format
    :param payload layer 3 packet, exactly 1482 bytes long, as a byte string
    """
    header = dst_address + src_address + ETHERTYPE
    frame_check_sequence = calculate_fcs(header + payload)
    return header + payload + frame_check_sequence