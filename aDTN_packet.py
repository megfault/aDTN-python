from utils import encrypt, decrypt
from scapy.all import Packet, LenField


class aDTNPacket(Packet):
    def __init__(self, *args, key=None, auto_encrypt=True, **kwargs):
        self.key = key
        self.auto_encrypt = auto_encrypt
        super().__init__(*args, **kwargs)

    def encrypt(self):
        key = self.key
        byteval = self.payload.build()  # better way to do it?
        encrypted = encrypt(byteval, key)
        self.remove_payload()
        # add_payload will try to figure out the type
        self.add_payload(bytes(encrypted))

    def decrypt(self):
        key = self.key
        byteval = self.payload.load
        decrypted = decrypt(byteval, key)
        self.remove_payload()
        # add_payload will try to figure out the type
        # encrypted is of Type nacl.secret.EncryptedMessage
        self.add_payload(aDTNInnerPacket(decrypted))

    # TODO delegate to encrypt/decrypt after building
    # TODO also breaks show2 and other methods where build is called twice
    def post_build(self, pkt, pay):
        if self.auto_encrypt and self.key is not None:
            return encrypt(pay, self.key)
        return pay

    # TODO misuse of method, find the right one
    def extract_padding(self, s):
        if self.auto_encrypt and self.key is not None:
            return decrypt(s, self.key), None
        return s

    def clone_attrs(self, clone):
        # TODO clone all keys
        clone.key = self.key
        clone.auto_encrypt = self.auto_encrypt
        return clone

    # TODO how to avoid such redundancy
    # scapy seems to have a oop structure problem
    def clone_with(self, payload=None, **kargs):
        pkt = super().clone_with(payload, **kargs)
        return self.clone_attrs(pkt)

    def copy(self):
        pkt = super().copy()
        return self.clone_attrs(pkt)


class aDTNInnerPacket(Packet):
    packet_len = 1460  # TODO get it from layer above, conf.padding_layer
    fields_desc = [LenField("len", default=None)]
    # TODO configure payload type as EncryptedMessage

    def post_build(self, pkt, pay):
        # add padding, will be calculated when calling show2
        # which basically builds and dissects the same packet
        pad_len = self.packet_len - len(pkt) - len(pay)
        # TODO check while adding payload
        if pad_len < 0:
            raise ValueError("Payload in inner packet too big")
        return pkt + pay + b'0' * pad_len

    def extract_padding(self, s):
        l = self.len
        if l > self.packet_len:
            raise ValueError("Payload in inner packet too big")
        return s[:l], s[l:]

