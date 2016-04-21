from binascii import hexlify, unhexlify
from nacl.utils import random as rand
from nacl.secret import SecretBox
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from logging import basicConfig, debug, DEBUG

basicConfig(filename='aDTN.log', level=DEBUG,
                    format='[%(relativeCreated)8d] %(message)s',)

def log(s):
    debug(s)

def generate_iv():
    return rand(SecretBox.NONCE_SIZE)


def encrypt(message, key, nonce_generator=generate_iv):
    return SecretBox(key).encrypt(message, nonce_generator())


def decrypt(encrypted, key):
    return SecretBox(key).decrypt(encrypted)

def hash_string(s):
    bytes = s.encode('utf-8')
    h = sha256(bytes, HexEncoder)
    return h.decode('utf-8')

def b2s(b):
    return hexlify(b).decode('utf-8')

def s2b(s):
    return unhexlify(s.encode('utf-8'))


