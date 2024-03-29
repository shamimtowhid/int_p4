#!/usr/bin/env python3

import argparse
import sys
import socket
import random
import struct
import datetime
from datetime import timezone
from essential_generators import DocumentGenerator

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField, LongField, Field
from scapy.layers.inet import _IPOption_HDR

from time import sleep

class Bit48Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")

    def i2m(self, pkt, x):
        return x.to_bytes(6, byteorder='big')

    def m2i(self, pkt, x):
        return int.from_bytes(x, byteorder='big')


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ ShortField("swid", 0),
                  IntField("qdepth", 0),
#                  Bit48Field("ingress_timestamp", 0),
                  Bit48Field("duration", 0)]

    def extract_padding(self, p):
                return "", p

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]


def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    #hexdump(pkt)
    sentence_generator = DocumentGenerator()
    try:
        for i in range(int(sys.argv[3])):
            if sys.argv[2] == "timestamp":
                dt = datetime.datetime.now(timezone.utc)
  
                utc_time = dt.replace(tzinfo=timezone.utc)
                payload = str(utc_time.timestamp()) + " " + sentence_generator.sentence()
            else:
                payload = "P4 is cool"

            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
                dst=addr, options= IPOption_MRI(count=0, swtraces=[])) / UDP(dport=4321, sport=1234) / payload

            pkt.show2()
            sendp(pkt, iface=iface)
            sleep(1)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()
