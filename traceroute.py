import socket
import argparse
import time
import struct


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
        help="Print a summary of how many probes were not answered for each hop."
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
        self.port = 33434
        self.destination_ip = socket.gethostbyname(self.destination)
        print(self.destination_ip)

    def run(self):
        while self.ttl < self.max_ttl:
            start_time = time.time()

            # receiver socket setup
            rec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            # set timeout
            timeout = struct.pack("ll", 5, 0)
            rec_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
            # bind
            rec_socket.bind(('', self.port))

            # sender socket setup
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

            # probe
            send_socket.sendto(b'', (self.destination, self.port))

            address = None
            complete = False
            tries = self.tries
            try_string = ""
            while tries > 0 and not complete:
                try:
                    _, address = rec_socket.recvfrom(1024)
                    end_time = time.time()
                    complete = True;
                except socket.error:
                    tries = tries - 1
                    try_string += "* "

            rec_socket.close()
            send_socket.close()

            if address:
                round_trip = round((end_time - start_time) * 1000, 1)
                print('{:<4} {} {} ms'.format(self.ttl, address[0], round_trip))
                if address[0] == self.destination_ip:
                    # done
                    break
            else:
                print("{:<4} {}".format(self.ttl, try_string))

            self.ttl += 1


if __name__ == '__main__':
    TracerouteInstance = Traceroute()
    TracerouteInstance.run()
