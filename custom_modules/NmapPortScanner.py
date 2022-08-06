import nmap
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

""" 
    Connects to given host at the given port to deteremine whether the host is up and state of the port.
    @Param host String: IP address or range 
    @Param port Striing: The connection port
    @Param verbose Boolean: Optional - If true, increase verbsoity
    @Param timeout Integer: Optional - Sets the time to give up
    @Param report Boolean: Optional - If true, print results to file
"""


def is_port_open(host=None, port=None, verbose=False, timeout=5, report=False):
    nm_scanner = None

    if not host == None and not port == None:
        nm_scanner = nmap.PortScanner()

        nm_scanner.scan(str(host), str(port))

        return nm_scanner
    else:
        message = "Expecting host and port arguments but received Host: {} and Port: {}".format(
            host, port
        )
        raise ValueError(message)
