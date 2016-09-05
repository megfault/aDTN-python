from pyadtn.utils import *
from nacl.utils import random
from nacl.secret import SecretBox


def test_Xcryption():
    msg = b'hello'
    key = random(SecretBox.KEY_SIZE)
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    assert msg == dec


def test_conversion():
    hello = b'hello'
    assert s2b(b2s(hello)) == hello


def test_mac_generator():
    mac = random_mac_address()
    digits = '0123456789abcdef'
    assert len(mac) == 17
    for i in range(17):
        if i % 3 == 2:
            assert mac[i] == ':'
        else:
            assert mac[i] in digits