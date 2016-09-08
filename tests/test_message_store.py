from pyadtn.message_store import DataStore
from pyadtn.utils import hash_string


def test_storage():
    msg = "test"
    ms = DataStore(db_filename="ds")
    ms.wipe()
    ms.add_object(msg)
    retrieved_msg = ms.get_data()[0]
    assert msg == retrieved_msg
    ms.wipe()


def test_wipe():
    msg = "test"
    ms = DataStore(db_filename="ds")
    ms.add_object(msg)
    l = ms.get_data(1)
    assert len(l) == 1
    ms.wipe()
    l = ms.get_data()
    assert len(l) == 0


def test_creation():
    msg = "test"
    ms = DataStore(db_filename="ds")
    ms.wipe()
    ms.add_object(msg)
    retrieved_msg = ms.get_data()[0]
    assert msg == retrieved_msg
    ms.wipe()


def test_deletion():
    msg = "test"
    idx = hash_string(msg)
    ms = DataStore(db_filename="ds")
    ms.wipe()
    ms.add_object(msg)
    ms.delete_data(idx)
    ms.add_object(msg)
    retrieved_msg = ms.get_data()
    assert len(retrieved_msg) == 0
    ms.wipe()


def test_repetion():
    msg = "test"
    ms = DataStore(db_filename="ds")
    ms.wipe()
    ms.add_object(msg)
    ms.add_object(msg)
    retrieved_msg = ms.get_data()
    assert len(retrieved_msg) == 1
    ms.wipe()
