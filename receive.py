#!/usr/bin/env python3
import sys
import struct
import json
import signal
import socket
import datetime
from datetime import timezone

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, Field
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR


class Bit48Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")

    def i2m(self, pkt, x):
        return x.to_bytes(6, byteorder='big')

    def m2i(self, pkt, x):
        return int.from_bytes(x, byteorder='big')


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

class SwitchTrace(Packet):
    fields_desc = [ ShortField("swid", 0),
                    IntField("qdepth", 0),
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

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

def get_timestamp(): 
    dt = datetime.datetime.now(timezone.utc)
  
    utc_time = dt.replace(tzinfo=timezone.utc)
    return str(utc_time.timestamp())


def handle_pkt(pkt):
    global DATA
    print("got a packet")
    receive_time = get_timestamp() # UTC_timestamp
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    host_ip = get_ip_address()
    if host_ip == dst_ip:
        key = src_ip+"_"+dst_ip+"_"+receive_time
        size = len(pkt) # in bytes
        send_time = pkt[Raw].load.decode('utf-8').split(" ")[0] # getting the send time from "timestamp random_interger"
        swtraces = []
        for i in range(len(pkt[IP].options[0].swtraces), 0, -1):
            tmp = {}
            tmp["duration"] = pkt[IP].options[0].swtraces[i-1].duration
            tmp["sw_id"] = pkt[IP].options[0].swtraces[i-1].swid
            tmp["qdepth"] = pkt[IP].options[0].swtraces[i-1].qdepth

            swtraces.append(tmp)

        data = { key: {
                        "pkt_size_byte" : size, 
                        "send_time" : send_time, 
                        "swtraces" : swtraces
                    }
                }

        print(data)
        DATA.append(data)
        sys.stdout.flush()

def create_handler(filename):
    def handler(signum, frame):
        save_data(filename)
        exit(0)
    return handler

def save_data(filename):
    global DATA
    print("Saving Data: ", len(DATA))
    with open(filename,"w+") as f:
        json.dump(DATA, f)

# global variable
DATA = []

def main():
    if len(sys.argv)<2:
        print('pass the hostname to save the data in json format')
        exit(1)

    filename = "./json_data/"+sys.argv[1]+".json"

    iface = 'eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
#   signal handler to detect the press of Ctrl+c, when detected the DATA variable is written in json format
    signal.signal(signal.SIGINT, create_handler(filename))

    sniff(filter="udp and port 4321", iface = iface,
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
