#! /usr/bin/python3

import argparse
import os
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.PortScanner import is_port_open as ipo
from custom_modules.NmapPortScanner import is_port_open as nmap
from custom_modules.LocalConfigParser import return_route
from custom_modules.PortScannerResultsHandler import handle_results as handler

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
    "-v", "--verbose", help="Increase output verbosity", action="store_true"
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

            if eport < sport:
                port_range = False
            else:
                ports = range(sport, eport)
                port_range = True
        else:
            sport = int(args.ports)

    if port_range:
        for port in ports:
            port_open = ipo(host, port, verbose, timeout)
            if port_open:
                print("{} is open".format(port))
    else:
        port_open = ipo(host, sport, None, False, timeout)

        if port_open:
            print("{} is open".format(port))


def run_verbose_mode(cust, args):
    global timeout
    global sport, eport, ports
    global port_range

    if args.addr:
        host = args.addr

    if args.timeout:
        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])

            if eport < sport:
                port_range = False
            else:
                ports = range(sport, eport)
                port_range = True
        else:
            sport = int(args.ports)

    msg = "Port Scanner"
    cmsg = cus(177, 200, 177, msg)
    print("\n\t\t\t\t{}\n".format(cmsg) + "-" * 75)

    if port_range:
        msg_host = "Scanning Host: {}".format(host)
        cus_msg_host = cus(170, 170, 255, msg_host)
        msg_ports = "Ports: {}-{}".format(sport, eport)
        cus_msg_ports = cus(200, 200, 245, msg_ports)
        print("{}{}\n".format(cus_msg_host, cus_msg_ports))

        for port in ports:
            port_open = ipo(host, port, verbose, timeout)
            if port_open:
                msg_port_open = "Port {} is open".format(port)
                cus_msg_port_open = cus(255, 255, 255, msg_port_open)
                print("{}".format(cus_msg_port_open))
            else:
                msg_port_closed = "Port {} is closed".format(port)
                cus_msg_port_closed = cus(100, 100, 100, msg_port_closed)
                print("{}".format(cus_msg_port_closed))
    else:
        msg_host = "Scanning Host: {}".format(host)
        cus_msg_host = cus(170, 170, 255, msg_host)
        msg_port = "Port: {}".format(sport)
        cus_msg_port = cus(200, 200, 245, msg_port)
        print("{}{}\n".format(cus_msg_host, cus_msg_port))

        port_open = ipo(host, sport, verbose, timeout)

        if port_open:
            msg_port_open = "Port {} is open".format(sport)
            cus_msg_port_open = cus(255, 255, 255, msg_port_open)
            print("{}".format(cus_msg_port_open))
        else:
            msg_port_closed = "Port {} is closed".format(sport)
            cus_msg_port_closed = cus(100, 100, 100, msg_port_closed)
            print("{}".format(cus_msg_port_closed))


def run_default_mode(cus, args):
    global timeout
    global sport, eport, ports
    global port_range

    if args.addr:
        host = args.addr

    if args.timeout:
        timeout = args.timeout

    if args.ports:
        if "-" in args.ports:
            ports_split = args.ports.split("-")
            sport = int(ports_split[0])
            eport = int(ports_split[1])

            if eport < sport:
                port_range = False
            else:
                ports = range(sport, eport)
                port_range = True
        else:
            sport = int(args.ports)

    if port_range:

        for port in ports:
            port_open = ipo(host, port, verbose, timeout)
            if port_open:
                msg_port_open = "Port {} is open".format(port)
                cus_msg_port_open = cus(255, 255, 255, msg_port_open)
                print("{}".format(cus_msg_port_open))
    else:
        port_open = ipo(host, sport, verbose, timeout)

        if port_open:
            msg_port_open = "Port {} is open".format(sport)
            cus_msg_port_open = cus(255, 255, 255, msg_port_open)
            print("{}".format(cus_msg_port_open))


# Use Nmap
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
        ports = args.ports

    scan_results = nmap(host, ports)

    handler(scan_results)

# Quiet mode
elif args.quiet:
    run_quiet_mode(cus, args)

# Level 1 verbose mode
elif args.verbose:
    run_verbose_mode(cus, args)

# Default mode run silently
else:
    run_default_mode(cus, args)


print(scan_results)
