from pyadtn.key_manager import KeyManager
from nacl.secret import SecretBox


def test_key_id_type():
    km = KeyManager()
    key_id = km.create_key()
    assert type(key_id) == str


def test_key_not_in_storage():
    km = KeyManager()
    key_id = km.create_key()
    km.keys = dict()
    assert key_id not in km.keys


def test_key_in_storage():
    km = KeyManager()
    key_id = km.create_key()
    km.save_all_keys()
    km.keys = dict()
    km.load_keys()
    assert key_id in km.keys


def test_randomness():
    km = KeyManager()
    key1 = km.get_fake_key()
    key2 = km.get_fake_key()
    assert key1 != key2


def test_stored_key_size():
    km = KeyManager()
    for key in km.keys:
        assert len(km.keys[key]) == SecretBox.KEY_SIZE