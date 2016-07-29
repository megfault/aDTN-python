from pyadtn.utils import *
from nacl.utils import random
from nacl.secret import SecretBox


def test_randomness():
    rand1 = generate_iv()
    rand2 = generate_iv()
    assert rand1 != rand2


def test_iv_length():
    rand = generate_iv()
    assert len(rand) == SecretBox.NONCE_SIZE


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
