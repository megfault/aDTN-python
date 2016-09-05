from binascii import hexlify, unhexlify
from nacl.utils import random as rand
from nacl.secret import SecretBox
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from random import randint
import fcntl, socket, struct
from logging import basicConfig, DEBUG, INFO, FileHandler, Formatter, getLogger


basicConfig(filename='debug.log', level=DEBUG,
            format='[%(created)f] %(threadName)s (%(thread)d) -- %(message)s', )
network_fh = FileHandler('network_events.log')
network_fh.setLevel(INFO)
formatter = Formatter('[%(asctime)s] %(message)s')
network_fh.setFormatter(formatter)
getLogger('').addHandler(network_fh)


def log_network(x):
    getLogger('').info(x)


def log_debug(x):
    getLogger('').debug(x)


def generate_iv():
    """
    Generate a random initialization vector of appropriate length for Salsa20.
    :return: random bytestring the size of a Salsa20 nonce (24 bytes)
    """
    return rand(SecretBox.NONCE_SIZE)


def encrypt(plaintext, key, nonce_generator=generate_iv):
    """
    Encrypt a bytestring with the given key using the Salsa20 algorithm.
    Encryption uses a new nonce by default, but can be overridden in case one needs a custom nonce.
    :param plaintext: bytestring to encrypt
    :param key: a 32 byte long bytestring
    :param nonce_generator: a function that returns a 24 byte long bytestring
    :return: bytestring containing the ciphertext
    """
    return SecretBox(key).encrypt(plaintext, nonce_generator())


def decrypt(ciphertext, key):
    """
    Decrypt a bytestring with the given key.
    :param ciphertext: a bytestring to decrypt
    :param key: a 32 byte long bytestring
    :return: resulting plaintext
    """
    sb = SecretBox(key)
    try:
        return sb.decrypt(ciphertext)
    except ValueError:
        debug("Nonce is invalid, probably wrong size.")
        raise Exception


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
