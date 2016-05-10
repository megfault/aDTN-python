from binascii import hexlify, unhexlify
from nacl.utils import random as rand
from nacl.secret import SecretBox
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from logging import basicConfig, debug, DEBUG

basicConfig(filename='aDTN.log', level=DEBUG,
            format='[%(relativeCreated)8d] %(message)s', )


def log(s):
    debug(s)


def generate_iv():
    """
    Generates a random initialization vector of appropriate length for Salsa20.
    :return: a random bytestring the size of a Salsa20 nonce (24 bytes)
    """
    return rand(SecretBox.NONCE_SIZE)


def encrypt(plaintext, key, nonce_generator=generate_iv):
    """
    Encrypts a bytestring with the given key using the Salsa20 algorithm.
    Uses a new nonce by default, but can be overridden in case one needs a custom nonce.
    :param plaintext: the bytestring to encrypt
    :param key: a 32 byte long bytestring
    :param nonce_generator: a function that returns a 24 byte long bytestring
    :return: a bytestring containing the ciphertext
    """
    return SecretBox(key).encrypt(plaintext, nonce_generator())


def decrypt(ciphertext, key):
    """
    Decrypt a bytestring with the given key.
    :param ciphertext: a bytestring to decrypt
    :param key: a 32 byte long bytestring
    :return: the resulting plaintext
    """
    return SecretBox(key).decrypt(ciphertext)


def hash_string(s):
    """
    Hashes the input string and converts the result to string format.
    :param s: a string to hash
    :return: the hash of the input string in string format.
    """
    b = s.encode('utf-8')
    h = sha256(b, HexEncoder)
    return h.decode('utf-8')


def b2s(b):
    """
    Converts a bytestring to a string.
    :param b: the bytestring to convert.
    :return: the decoded bytestring in string format.
    """
    return hexlify(b).decode('utf-8')


def s2b(s):
    """
    Converts a string to a bytestring.
    :param s: the string to convert
    :return: the bytestring conversion of the input string.
    """
    return unhexlify(s.encode('utf-8'))


