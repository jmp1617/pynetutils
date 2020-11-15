#!/bin/bin/python
import argparse
import socket
from time import time
import sys
import os
import select
import struct


INTERFACE = "wlp4s0"
ICMP_ECHO_REQUEST = 8


class Ping:
    def __init__(self):
        args = self.init()
        self.destination = args.destination
        self.count = args.count
        self.wait = args.wait
        self.packetsize = args.packetsize
        self.timeout = args.timeout
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

    def craft_packet(self, identification):
        checksum = 0
        header = struct.pack(
            "!BBHHH", ICMP_ECHO_REQUEST, 0, checksum, identification, 1
        )
        pad_bytes = []
        start_val = 0x42
        for i in range(startVal, startVal + self.packetsize):
            pad_bytes += [(i & 0xff)]
        data = bytes(pad_bytes)
        checksum = self.checksum(header + data)
        header = struct.pack(
            "!BBHHH", ICMP_ECHO_REQUEST, 0, checksum, identification, 1
        )

        return header + data

    def checksum(self, source_string):
        count_to = (int(len(source_string) / 2)) * 2
        total = 0
        count = 0
        low = 0
        high = 0
        while count < count_to:
            if sys.byteorder == "little":
                low = source_string[count]
                high = source_string[count + 1]
            else:
                low = source_string[count + 1]
                high = source_string[count]
            total = total + (ord(high) * 256 + ord(low))
            count += 2

        if count_to < len(source_string):
            low = source_string[len(source_string) - 1]
            total += ord(low)

        total &= 0xffffffff

        total = (total >> 16) + (total & 0xffff)
        total += (total >> 16)
        answer = ~total & 0xffff
        answer = socket.htons(answer)
        return answer

    def header2dict(self, names, struct_format, data):
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    def ping(self):
        identification = os.getpid() & 0xFFFF

        # send
        packet = self.craft_packet(identification)
        self.s.sendto(packet, (self.destination, 1))
        sent_time = time()

        # receive
        timeout = self.timeout / 1000.0

        while True:
            select_start = time()
            inputready, outputready, exceptready = select.select([self.s], [], [], timeout)
            select_duration = time() - select_start
            if not inputready:
                return sent_time, None

            receive_time = time()

            packet_data, address = self.s.recvfrom(2048)

            icmp_header_dict = dict(
                zip(
                    names=["type", "code", "checksum", "packet_id", "seq_number"],
                    data=struct.unpack("!BBHHH", packet_data[20:28])
                )
            )

            if icmp_header_dict["packet_id"] == identification:
                return sent_time, receive_time

            timeout = timeout - select_duration
            if timeout <= 0:
                return sent_time, None

    def init(self):
        parser = argparse.ArgumentParser(description='Python Ping Utility')
        parser.add_argument(
            "destination", help="destination address", type=str
        )
        parser.add_argument(
            "-c", "--count", type=int, help="Stop after sending (and receiving) count response packets.", default=-1
        )
        parser.add_argument(
            "-i", "--wait", type=int, help="Time in between sending packet, default is 1 second.", default=1
        )
        parser.add_argument(
            "-s", "--packetsize", type=int, help="Number of data bytes sent. Default is 56.", default=56
        )
        parser.add_argument(
            "-t", "--timeout", type=int, help="Time before ping exits regardless of packets received.", default=30
        )
        return parser.parse_args()


if __name__ == '__main__':
    PingInstance = Ping()
    print(PingInstance.ping())
