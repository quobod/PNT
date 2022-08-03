#! /usr/bin/python3

import argparse
from ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from PortScanner import check_port as chp


cus = cms["custom"]
msg = None
timeout = None
port_range = False
sport = 1
eport = 65534
ports = range(sport, eport)
host = "192.168.1.1"

parser = argparse.ArgumentParser(description="Remote host port scanner")

group = parser.add_mutually_exclusive_group()

""" group arguments """

# verbosity level
group.add_argument(
    "-v", "--verbose", help="Increase output verbosity", action="count", default=0
)

# run program silently
group.add_argument(
    "-q", "--quiet", help="Silently run the program", action="store_true"
)

""" positional arguments """

# host address
parser.add_argument(
    "-a",
    "--addr",
    help="The target host's IP address, defaults to 192.168.1.1",
    default=host,
)

# connection timeout
parser.add_argument(
    "-t",
    "--timeout",
    type=float,
    help="Set connection time out in seconds - e.g. 0.2 or 10.",
)

# port or port range
parser.add_argument(
    "-p",
    "--ports",
    help="Select which port or range of ports to scan; e.g. -p 22 or -p 1-1024.",
)

# parse arguments
args = parser.parse_args()


def run_quiet_mode(cus, args):
    msg = "Run program silently"
    cmsg = cus(177, 200, 177, msg)
    print("\n\t\t\t{}\n".format(cmsg) + "-" * 75 + "\n")

    if args.addr:
        host = args.addr

    if args.timeout:
        global timeout

        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])
            port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        print("Scanning host {}'s ports {}-{}".format(host, sport, eport))
        chp(host, sport, eport, False, timeout)

    else:
        print("Scanning host {}'s port {}".format(host, sport))
        chp(host, sport, None, False, timeout)


def run_verbose_level_2_mode(cus, args):
    msg = "Running program with level {} verbosity".format(args.verbose)
    cmsg = cus(177, 230, 177, msg)
    print("\n\t\t\t{}\n".format(cmsg) + "-" * 75 + "\n")

    if args.addr:
        host = args.addr

    if args.timeout:
        global timeout

        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])
            port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        print("Scanning host {}'s ports {}-{}".format(host, sport, eport))
        chp(host, sport, eport, True, timeout)
    else:
        print("Scanning host {}'s port {}".format(host, sport))
        chp(host, sport, None, True, timeout)


def run_verbose_level_1_mode(cus, args):
    msg = "Running program with level {} verbosity".format(args.verbose)
    cmsg = cus(177, 240, 177, msg)
    print("\n\t\t\t{}\n".format(cmsg) + "-" * 75 + "\n")

    if args.addr:
        host = args.addr

    if args.timeout:
        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])
            port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        print("Scanning host {}'s ports {}-{}".format(host, sport, eport))
        chp(host, sport, eport, True, timeout)
    else:
        print("Scanning host {}'s port {}".format(host, sport))
        chp(host, sport, None, True, timeout)


def run_default_mode(cus, args):
    msg = "Run program with default config"
    cmsg = cus(177, 200, 177, msg)
    print("\n\t\t\t{}\n".format(cmsg) + "-" * 75 + "\n")

    if args.addr:
        host = args.addr

    if args.timeout:
        global timeout

        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])
            port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        print("Scanning host {}'s ports {} - {}".format(host, sport, eport))
        chp(host, sport, eport, False, timeout)
    else:
        print("Scanning host {}'s port {}".format(host, sport))
        chp(host, sport, None, False, timeout)


# Quiet mode
if args.quiet:
    run_quiet_mode(cus, args)

# Level 2 verbose mode
elif args.verbose >= 2:
    run_verbose_level_2_mode(cus, args)

# Level 1 verbose mode
elif args.verbose >= 1:
    run_verbose_level_1_mode(cus, args)

# Default mode run silently
else:
    run_default_mode(cus, args)
