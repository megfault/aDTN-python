import pyadtn.aDTN
import pytest


@pytest.fixture(autouse=True)
def no_networking(monkeypatch):
    def do_nothing(*args,**kwargs):
        return
    monkeypatch.setattr(pyadtn.aDTN, 'sniff', do_nothing)
    monkeypatch.setattr(pyadtn.aDTN, 'sendp', do_nothing)


def test_start_stop():
    adtn_instance = pyadtn.aDTN.aDTN(10, 10, "wlp3s0", "ds")
    assert adtn_instance._sending is None
    assert adtn_instance._sniffing is None
    assert adtn_instance._thread_send is None
    assert adtn_instance._thread_receive is None
    adtn_instance.start()
    assert adtn_instance._sending
    assert adtn_instance._sniffing
    assert adtn_instance._thread_send.is_alive()
    assert adtn_instance._thread_receive.is_alive()
    adtn_instance.stop()
    assert not adtn_instance._sending
    assert not adtn_instance._sniffing
    assert adtn_instance._scheduler.empty()
    assert not adtn_instance._thread_send.is_alive()
    assert not adtn_instance._thread_receive.is_alive()


def test_sending_pool_size():
    adtn_instance = pyadtn.aDTN.aDTN(10, 10, "wlp3s0", "ds")
    adtn_instance.start()
    assert len(adtn_instance._sending_pool) >= 10
    adtn_instance.data_store.wipe()
    assert len(adtn_instance._sending_pool) >= 10
    adtn_instance._prepare_sending_pool()
    assert len(adtn_instance._sending_pool) >= 10
    adtn_instance._send()
    assert len(adtn_instance._sending_pool) >= 10
    for i in range(5):
        adtn_instance.data_store.add_object("ohai: {}".format(i))
    adtn_instance._send()
    assert len(adtn_instance._sending_pool) >= 10
    adtn_instance.stop()
    assert len(adtn_instance._sending_pool) >= 10
    adtn_instance.data_store.wipe()
