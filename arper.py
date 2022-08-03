#! /usr/bin/python3

import argparse
import re
import os
import sys
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.PatternConstants import IP4, IPv4, IPv4_network
from custom_modules.LocalConfigParser import (
    return_arp_results as rar,
    return_gateway_addr,
    return_local_ip_address,
    return_local_ip_address_by_name,
    return_local_mac_address,
    return_local_mac_address_by_iface_name,
    return_local_route,
    return_mac_by_ip_address,
    return_route,
)


def error_handler(*args):
    cus = cms["custom"]
    arg = args[0]
    cargs = cus(254, 64, 4, arg)
    print("{}".format(cargs))
    sys.exit(os.EX_USAGE)


def warning_handler(*args):
    cus = cms["custom"]
    arg = args[0]
    cargs = cus(254, 224, 224, arg)
    print("{}".format(cargs))
    sys.exit(os.EX_USAGE)


desc = "A tool that displays and can print reports about the hosts connected to the network."
epil = "This program needs adminstrative access to perform many, if not, all of it's tasks."
console_width_size = os.get_terminal_size(sys.__stderr__.fileno())[0]
warning_message = (
    "*" * 28
    + "\n|"
    + " " * 7
    + "Warning"
    + " " * 12
    + "|\n|"
    + " " * 26
    + "|\n"
    + "*" * 28
    + "\nThis program need admin access\n"
)
if_name, if_addr, gateway = return_route()
cus = cms["custom"]
msg = None
match = None


def print_local_route():
    msg = cms["custom"]
    local_route = return_route()
    dash = msg(245, 220, 199, "-")
    title = msg(200, 255, 200, "Local network interface")
    print(
        "{}\n".format(title)
        + " {}".format(msg(255, 255, 255, "Name"))
        + " " * 5
        + "\t  {}".format(msg(255, 255, 255, "Address"))
        + " " * 5
        + "\t\t {}".format(msg(255, 255, 255, "Gateway"))
    )
    print(dash * 29)
    print(*local_route, sep="\t\t")
    print("\n")


def print_local_mac():
    msg = cms["custom"]
    local_mac = return_local_mac_address()
    dash = msg(245, 220, 199, "-")
    title = msg(200, 255, 200, "Local network interface hardware address")
    print(
        "{}\n".format(title)
        + " {}".format(msg(255, 255, 255, "Name"))
        + " " * 5
        + "\t  {}".format(msg(255, 255, 255, "MAC"))
    )
    print(dash * 21)
    print("{}\t\t{}".format(if_name, local_mac))
    print("\n")


parser = argparse.ArgumentParser(description=desc, epilog=epil)

parser.error = error_handler

""" group optional arguments """

group = parser.add_mutually_exclusive_group()

# Increase verbosity
group.add_argument(
    "-v",
    "--verbose",
    dest="verbose",
    action="store_true",
    help="Increase output verbosity",
)

# Run silently
group.add_argument(
    "-q",
    "--quiet",
    dest="verbose",
    action="store_false",
    help="Silently run program. Runs with the arp command.",
)

""" positional arguments """

# Print local routing table
parser.add_argument(
    "-l", "--local", action="store_true", dest="local", help="Print local routing table"
)

# Print gateway address
parser.add_argument(
    "-g", "--gateway", action="store_true", dest="gateway", help="Print gateway address"
)

# Run program
parser.add_argument(
    "-a",
    "--arp",
    help="ARP to host or network e.g. --arp 192.167.45.3 or --arp 10.1.10.1/8.",
)

# Set timeout. Works with the arp command
parser.add_argument(
    "-t",
    "--timeout",
    help="Set the number of seconds to give up. Works with the arp command.",
    type=int,
)

# Update system cache. Works with the arp command
parser.add_argument(
    "-c",
    "--cache",
    action="store_true",
    help="Whether or not to refresh system's arp cache.",
)

# Print report. Works with the arp command
parser.add_argument(
    "-r",
    "--report",
    action="store_true",
    help="Print results to a text file. Defaults to no. Works with the arp command.",
)

# Print network interface hardware address
parser.add_argument(
    "-m",
    "--mac",
    action="store_true",
    dest="mac",
    help="Print local iface hardware address",
)

# parse arguments
args = parser.parse_args()

if not os.geteuid() == 0:
    warning_handler(warning_message)

""" ARP Request  """
_target = "{}/24".format(gateway)
_timeout = None
_cache = None
_verbose = None
_report = None


if args.arp:
    _target = args.arp

if args.timeout:
    _timeout = args.timeout

if args.verbose:
    _verbose = True
else:
    _verbose = False

if args.cache:
    _cache = True

if args.report:
    _report = True

# print("Target,  Timeout,  Cache,  Verbose,  Report")
# print("{}  {}  {}  {}  {}".format(_target, _timeout, _cache, _verbose, _report))

if _verbose:
    print("Arping\n\tTarget\t\t\tTimeout\t\tCache\t\tVerbose\t\tReport")
    print(
        "\t{}\t\t{}\t\t{}\t\t{}\t\t{}".format(
            _target, _timeout, _cache, _verbose, _report
        )
    )

rar(_target, _timeout, _cache, _verbose, _report)


""" Gateway Request """
if args.gateway:
    gwa = return_gateway_addr()
    print("Gateway: {}".format(gwa))


""" Local Route Request """
if args.local:
    print_local_route()


""" Iface Hardware Address Request  """
if args.mac:
    print_local_mac()
