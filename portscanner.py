#! /usr/bin/python3

import argparse
import os
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.PortScanner import check_port as chp
from custom_modules.NmapPortScanner import scan_port_config as nmap
from custom_modules.LocalConfigParser import return_route

cus = cms["custom"]
msg = None
timeout = None
verbose = None
report = None
port_range = False
sport = None
eport = None
netface, local_addr, host = return_route()
scan_results = ""

desc = "This program scans the given port(s) of the given host"
epil = "Scan a port or range of ports of hosts on the network"
vers = "%prog 0.1"


def error_handler(*args):
    cus = cms["custom"]
    arg = args[0]
    cargs = cus(254, 64, 4, arg)
    print("{}".format(cargs))
    os.system("exit")


parser = argparse.ArgumentParser(description=desc, epilog=epil)

parser.error = error_handler

parser.version = vers

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
    help="The target host's IP address; e.g. -a 110.2.77.83. Defaults to 192.168.1.1",
    default=host,
)

# connection timeout
parser.add_argument(
    "-t",
    "--timeout",
    type=float,
    help="Set connection time out in seconds; e.g. -t 0.2 or -t 10.",
)

# port or port range
parser.add_argument(
    "-p",
    "--ports",
    help="Select which port or range of ports to scan; e.g. -p 22 or -p 1-1024.",
)

# use nmap port scanning
parser.add_argument("-n", "--nmap", action="store_true", help="Use Nmap port scanning")

# print results to file
parser.add_argument(
    "-r", "--report", help="Prints scan results to file", action="store_true"
)

# parse arguments
args = parser.parse_args()


def run_quiet_mode(cus, args):
    global timeout
    global sport, eport, ports
    global port_range

    msg = "Silently running program"
    cmsg = cus(177, 200, 177, msg)
    # print("\n\t\t\t{}\n".format(cmsg) + "-" * 75 + "\n")

    if args.addr:
        host = args.addr

    if args.timeout:
        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])
            ports = (sport, eport)
            port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        chp(host, ports, None, False, timeout)
    else:
        chp(host, sport, None, False, timeout)


def run_verbose_level_1_mode(cus, args):
    msg = "Running program with level {} verbosity".format(args.verbose)
    cmsg = cus(177, 240, 177, msg)

    global port_range

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
            ports = (sport, eport)
            port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        chp(host, ports, None, True, timeout)
    else:
        chp(host, sport, None, True, timeout)


def run_default_mode(cus, args):
    msg = "Run program with default config"
    cmsg = cus(177, 200, 177, msg)

    global port_range, sport, eport

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
            ports = (sport, eport)
            port_range = True
        else:
            sport = int(args.ports)
    else:
        port_range = False

    if port_range:
        chp(host, ports, None, False, timeout)
    else:
        chp(host, sport, None, False, timeout)


if args.nmap:
    if args.addr:
        host = args.addr

    if args.timeout:
        timeout = args.timeout

    if args.verbose:
        verbose = True

    if args.report:
        report = True

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])
            port_range = True
        else:
            port_range = False
            sport = int(args.ports)

    global scan_results

    if port_range:
        scan_results = nmap(host, (sport, eport), None, verbose, timeout, report)
    else:
        scan_results = nmap(host, sport, eport, verbose, timeout, report)


# Quiet mode
elif args.quiet:
    run_quiet_mode(cus, args)

# Level 1 verbose mode
elif args.verbose >= 1:
    run_verbose_level_1_mode(cus, args)

# Default mode run silently
else:
    run_default_mode(cus, args)


print(scan_results)
