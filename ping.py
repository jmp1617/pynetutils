#!/usr/bin/python2.7
# jmp1617 - Ping
# Python 2.7

import argparse
import socket
import time
import sys
import os
import select
import struct


ICMP_ECHO_REQUEST = 8


def checksum(source_string):
    # calculate checksum as per ping.c + spec documentation
    # correctness tested with wireshark
    count_to = (int(len(source_string) / 2)) * 2
    total = 0
    count = 0
    while count < count_to:
        low = source_string[count]
        high = source_string[count + 1]
        total = total + (ord(high) * 256 + ord(low))
        count += 2
    if count_to < len(source_string):
        low = source_string[len(source_string) - 1]
        total += ord(low)
    total &= 0xffffffff
    total = (total >> 16) + (total & 0xffff)
    total += (total >> 16)
    result = ~total & 0xffff
    result = socket.htons(result)
    return result


def parse_args():
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


class Ping:
    def __init__(self):
        args = parse_args()
        self.host = args.destination
        self.destination = socket.gethostbyname(args.destination)
        self.count = args.count
        self.wait = args.wait
        self.packetsize = args.packetsize
        self.timeout = args.timeout
        self.transmitted = 0
        self.received = 0
        self.total_time = 0
        if self.timeout < 30:
            self.timeout = 30
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))  # init socket

    def craft_packet(self, identification, sequence):
        check = 0  # use an empty checksum value to create a mirror header in order to calculate the checksum
        header = struct.pack(
            "!BBHHH", ICMP_ECHO_REQUEST, 0, check, identification, sequence
        )
        data = bytes(self.packetsize * 'A')  # set the data
        check = checksum(header + data)  # get the correct checksum
        header = struct.pack(  # generate the correct header
            "!BBHHH", ICMP_ECHO_REQUEST, 0, check, identification, sequence
        )
        return header + data  # return the packet

    # helper to print the results line
    def display_results_line(self, res):
        self.total_time += round((res[1] - res[0]) * 1000, 1)
        print(
            "{} bytes from {}: icmp_seq={} ttl={} time={} ms".format(
                res[2],
                self.destination,
                res[3]['seq_number'],
                res[4]['ttl'],
                round((res[1] - res[0]) * 1000, 1)  # get round trip time
            )
        )

    def ping(self, sequence):
        # use the process id as the unique identifier
        identification = os.getpid()+1000 & 0xFFFF
        # send
        packet = self.craft_packet(identification, sequence)
        try:
            self.s.sendto(packet, (self.destination, 1))
            self.transmitted += 1
        except socket.error as e:
            print("Unable to resolve " + self.destination + str(e))
            exit()

        sent_time = time.time()
        # receive
        timeout = self.timeout / 1000.0  # get correct unit
        # loop until we get a response with our identification number
        while True:
            select_start = time.time()  # use select to keep track of timeout
            input_ready, o, e = select.select([self.s], [], [], timeout)
            select_time = time.time() - select_start
            if not input_ready:  # if input fails return
                return sent_time, -1, None, None, None
            receive_time = time.time()  # store time of reception
            packet_data, address = self.s.recvfrom(2048)  # recieve the data

            # convert received data to dictionary for easy access
            icmp_header_dict = dict(
                zip(
                    [
                        "type", "code", "checksum", "packet_id", "seq_number"
                    ],
                    struct.unpack("!BBHHH", packet_data[20:28])
                )
            )
            # unpack the ip header and convert to dict
            ip_header_dict = dict(
                zip(
                    [
                        "version", "type", "length", "id", "flags", "ttl", "protocol", "checksum", "src_ip", "dest_ip"
                    ],
                    struct.unpack("!BBHHHBBHII", packet_data[:20])
                )
            )
            if icmp_header_dict["packet_id"] == identification:  # this matches the packet we sent
                # return data for printing
                self.received += 1
                return sent_time, receive_time, len(packet_data) - 20, icmp_header_dict, ip_header_dict
            timeout = timeout - select_time  # if timeout is reached, return
            if timeout <= 0:
                return sent_time, None, None, None, None  # times out return

    def run(self):
        print("PING {} ({}) {}({}) bytes of data.".format(
            self.host, self.destination, self.packetsize, self.packetsize+28
        ))
        seq = 1
        packets = self.count
        # default self.count is -1 so while will run forever else will reach zero
        while packets != 0:
            result = self.ping(seq)  # send a ping
            if result[1] == -1:
                print("Unreachable")
            elif result[1] is None:
                print("Timeout")
            else:
                self.display_results_line(result)  # display the results
            time.sleep(self.wait)  # wait the designated wait time
            seq += 1  # update sequence num
            packets -= 1  # update count
        print("--- {} ping statistics ---".format(self.host))
        print("{} packets transmitted, {} received, {}% packet loss, time {}ms".format(
            self.transmitted,
            self.received,
            round((float(self.transmitted - self.received) / self.transmitted) * 100),
            self.total_time
        ))


if __name__ == '__main__':
    PingInstance = Ping()
    PingInstance.run()
