from argparse import ArgumentError
import nmap
from sympy import false
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.Printer import print_this as prt
from custom_modules.TypeTester import (
    arg_is_a_dict,
    arg_is_a_list,
    arg_is_a_string,
    arg_is_a_tuple,
    arg_is_an_int,
    arg_is_a_float,
)

custom = cms["custom"]


def is_port_open(host=None, port=None, verbose=False, timeout=5, report=False):
    if not host == None and not port == None:
        port = str(port).strip()
        nm_scanner = nmap.PortScanner()
        try:
            nm_scanner.scan(host, port)
            state = nm_scanner[host].state()
            proto = nm_scanner[host].all_protocols()
            tcp_keys = nm_scanner[host]["tcp"].keys()
            command = nm_scanner.command_line()
            scan_info = nm_scanner.scaninfo()
            if verbose:
                print("Command: {}".format(command))
                print("Host State: {}".format(state))
                header = "Port{}{}State{}{}{}Response{}{}Service".format(
                    "\t", "\t", "\t", "\t", "\t", "\t", "\t"
                )
                print("{}".format(header))
                print("-" * len(header) * 3)
                for v in tcp_keys:
                    tcp = nm_scanner[host]["tcp"][v]
                    _state = tcp["state"]
                    _status = tcp["reason"]
                    _service = tcp["name"]
                    print("{}\t\t{}\t\t{}\t\t{}".format(v, _state, _status, _service))
        except KeyError as ke:
            msg = custom(255, 100, 88, "Key: {} does not exist".format(ke))
            print("\nError: {}\n".format(msg))
    else:
        raise ArgumentError(
            "Expecting host and port arguments but received {} and {}".format(
                host, port
            )
        )


def start_scan(host, start_port, verbose, timeout, report):
    if arg_is_a_tuple(start_port) or arg_is_a_list(start_port):
        port_range = "{}-{}".format(start_port[0], start_port[1])
        is_port_open(host, port_range, verbose, timeout, report)
    else:
        is_port_open(host, start_port, verbose, timeout, report)


def scan_port_config(
    host=None, start_port=None, end_port=None, verbose=None, timeout=None, report=None
):
    _host = None
    _sport = None
    _eport = None
    _verbose = None
    _timeout = None
    _report = None
    _port_range = None
    _ports = False

    if not host == None and len(host) > 0:
        _host = host

    if not start_port == None:
        if arg_is_a_tuple(start_port) or arg_is_a_list(start_port):
            if len(start_port) == 2:
                if start_port[1] > start_port[0]:
                    _sport = start_port[0]
                    _eport = start_port[1]
                    _ports = True
                    _port_range = start_port
                else:
                    _sport = start_port[0]
                    _eport = None
                    _ports = False
                    _port_range = None

        elif (
            arg_is_an_int(start_port)
            and arg_is_an_int(end_port)
            and end_port > start_port
        ):
            _sport = start_port
            _eport = end_port
            _ports = True
            _port_range = range(_sport, _eport)

        else:
            _sport = start_port
            _eport = None
            _ports = False
            _port_range = None

    if not verbose == None:
        _verbose = verbose

    if not timeout == None and (arg_is_an_int(timeout) or arg_is_a_float(timeout)):
        _timeout = timeout

    if not report == None:
        _report = report

    if _ports:
        scan_action(_host, _port_range, _eport, _verbose, _timeout, _report)
        start_scan(_host, _port_range, _verbose, _timeout, _report)
    else:
        scan_action(_host, _sport, _eport, _verbose, _timeout, _report)
        start_scan(_host, _sport, _verbose, _timeout, _report)


def scan_action(host, sport, eport, verbose, timeout, report):
    cus = cms["custom"]
    msg = None

    if (arg_is_a_tuple(sport) or arg_is_a_list(sport)) and len(sport) == 2:
        start = sport[0]
        end = sport[1]
        msg = "Ports {}-{}".format(start, end)

    elif arg_is_an_int(sport) and arg_is_an_int(eport):
        msg = "Ports {}-{}".format(sport, eport)
    else:
        msg = "Port {}".format(sport)

    if verbose:
        print(
            "Scanning Host {}'s {}\nVerbose? {}\nTimeout? {}\nReport? {}\n".format(
                host, msg, verbose, timeout, report
            )
        )
