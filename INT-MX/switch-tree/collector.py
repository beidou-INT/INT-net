#!/usr/bin/env python3
import sys

from scapy.all import (
    FieldLenField,
    IntField,
    IPOption,
    IP,
    Packet,
    PacketListField,
    Field,
    ShortField,
    IPField,
    BitField,
    hexdump,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def handle_pkt(pkt):
    print("==================================================")
    ip_options = pkt[IP].options
    if ip_options:
        hexdump(pkt)
        print(ip_options)
    
    sys.stdout.flush()


class IPOption_INT(IPOption):
    name = "INT"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", 24, fmt="B"),
                    BitField("swid", 0, 8),
                    BitField("dataType", 0, 8),
                    BitField("traceid", 0, 16),
                    BitField("dataSize", 0, 16),
                    IPField("dataSrc", 0),
                    IPField("dataDst", 0),
                    TimeField("timestamp", 1704194795000, 48),
                    BitField("undefined", 0, 16)]

def main():
    iface = 'eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="ip", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
