from scapy.all import LenField, Packet


class InnerPacket(Packet):
    packet_len = 1500
    name = "foo"
    fields_desc = [LenField("len", default=None)]

    def post_build(self, pkt, pay):
        # add padding, will be calculated when calling show2
        # which basically builds and dissects the same packet
        pad_len = self.packet_len - len(pkt)
        return pkt + b'0' * pad_len

    def extract_padding(self, s):
        l = self.len
        return s[:l], s[l:]
