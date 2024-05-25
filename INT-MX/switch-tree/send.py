#!/usr/bin/env python3

import socket
import sys
from time import sleep
import random
from scapy.all import (
    IP,
    UDP,
    Ether,
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    IPField,
    BitField,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


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
                    BitField("timestamp", 1704194795000, 48),
                    BitField("duration", 0, 16)]

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: "selfHost, <message>"')
        exit(1)

    selfAddr = sys.argv[1]
    message = sys.argv[2]

    addrs = [
        '10.0.1.2',
        '10.0.1.3',
        '10.0.2.2',
        '10.0.2.3',
        '10.0.3.2',
        '10.0.3.3',
        '10.0.4.2',
        '10.0.4.3'
    ]

    for addr in addrs:
        if selfAddr != addr:
            # print(addr)
            # dst = socket.gethostbyname(addr)
            # print(dst)
            iface = get_if()
            addr = socket.gethostbyname(addr)
            sendNum = random.randint(1, 15)
            for i in range(sendNum):
                pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
                    dst=addr) / UDP(
                        dport=4321, sport=1234) / message
                
                sendp(pkt, iface=iface)
                sleep(1)
        else:
            continue


 #   pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
 #       dst=addr, options = IPOption_MRI(count=2,
 #           swtraces=[SwitchTrace(swid=0,qdepth=0), SwitchTrace(swid=1,qdepth=0)])) / UDP(
 #           dport=4321, sport=1234) / sys.argv[2]
    # pkt.show2()
    #hexdump(pkt)
    # try:
    #   for i in range(int(sys.argv[3])):
    #     sendp(pkt, iface=iface)
    #     sleep(1)
    # except KeyboardInterrupt:
    #     raise


if __name__ == '__main__':
    main()
