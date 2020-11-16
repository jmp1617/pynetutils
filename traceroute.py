#!/usr/bin/python2.7
# jmp1617 - Traceroute
# Python 2.7

import socket
import argparse
import time
import struct
import os


def parse_args():
    parser = argparse.ArgumentParser(description='Python Traceroute Utility')
    parser.add_argument(
        "destination", help="destination address", type=str
    )
    parser.add_argument(
        "-m",
        "--max_ttl",
        help="Specifies the maximum number of hops (max time-to-live value) traceroute will probe.",
        type=int,
        default=30
    )
    parser.add_argument(
        "-n",
        "--numerical",
        help="Print hop addresses numerically rather than symbolically and numerically.",
        action='store_true'
    )
    parser.add_argument(
        "-q",
        "--nqueries",
        help="Set the number of probes per ttl to nqueries.",
        type=int,
        default=3
    )
    parser.add_argument(
        "-S",
        "--summery",
        help="Print a summary of how many probes were not answered for each hop.",
        action="store_true"
    )
    return parser.parse_args()


class Traceroute:
    def __init__(self):
        args = parse_args()
        self.destination = args.destination
        self.max_ttl = args.max_ttl
        self.print_numerical = args.numerical
        self.tries = args.nqueries
        self.show_summary = args.summery
        self.ttl = 1
        self.packet_size = 60  # UDP payload size
        self.port = 33434  # UDP port to use
        self.destination_ip = socket.gethostbyname(self.destination)  # get the ip from the host

    def run(self):
        print("Traceroute to {} ({}), {} max hops, {} byte packets".format(
            self.destination, self.destination_ip, self.max_ttl, self.packet_size
        ))
        destination_reached = False
        # until the destination is reached or the max hops has been reached
        while self.ttl < self.max_ttl and not destination_reached:
            # receiver socket setup
            rec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            # set timeout
            timeout = struct.pack("ll", 5, 0)
            rec_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
            # bind
            rec_socket.bind(('', self.port))

            # sender socket setup
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname("udp"))
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)  # specify the ttl

            addresses = []
            complete = False
            tries = self.tries
            failed_tries = 0
            # try tries amount of times to probe an intermediate
            while tries > 0 and not complete:
                try:
                    start_time = time.time()  # track start time
                    send_socket.sendto(b'A' * self.packet_size, (self.destination, self.port))  # send a packet_size udp
                    _, address = rec_socket.recvfrom(2048)  # try to catch the hop limit reached icmp message from hop
                    end_time = time.time()  # capture the end time
                    tries = tries - 1
                    addresses.append((address[0], start_time, end_time))  # store the info gathered for printing
                except socket.error:  # if socket timed out or no response
                    tries = tries - 1
                    failed_tries += 1
                    addresses.append((0, 0, 0))  # store a loss

            # reset the sockets for next ttl
            rec_socket.close()
            send_socket.close()

            # check to see if the responding servers are all the same
            all_same = True
            temp_address = addresses[0][0]
            for address in addresses:
                if temp_address != address[0]:
                    all_same = False

            # if they are all the same, condense the print line
            if all_same:
                if temp_address == 0:
                    line = "{} ".format(self.ttl)
                    for _ in addresses:
                        line = line + "* "
                else:
                    if self.print_numerical:
                        line = "{} {} ".format(self.ttl, temp_address)
                    else:
                        try:
                            host = socket.gethostbyaddr(temp_address)[0]
                        except Exception:
                            host = temp_address
                        line = "{} {} ({}) ".format(self.ttl, host, temp_address)
                    for address in addresses:
                        line = line + "{} ms ".format(round((address[2]-address[1])*1000, 2))
            # if they are not all the same, print info on each
            else:
                line = "{} ".format(self.ttl)
                for address in addresses:
                    if address[0] == 0:
                        line = line + "* "
                    else:
                        if self.print_numerical:
                            line = line + "{} {} ms ".format(address[0], round((address[2]-address[1])*1000, 2))
                        else:
                            try:
                                host = socket.gethostbyaddr(adress[0])[0]
                            except Exception:
                                host = address[0]
                            line = line + "{} ({}) {} ms ".format(address[0], host, round((address[2]-address[1])*1000, 2))

            # append loss info
            if self.show_summary:
                line = line + "({}% loss)".format(round((float(failed_tries) / self.tries)*100, 2))

            print(line)

            # check to see if the initial destination has been reached
            for address in addresses:
                # sometimes resolution changes mid run, recheck hosts ip
                if address[0] == socket.gethostbyname(self.destination):
                    destination_reached = True
                    break

            # up the ttl one hop
            self.ttl += 1


if __name__ == '__main__':
    TracerouteInstance = Traceroute()
    TracerouteInstance.run()
