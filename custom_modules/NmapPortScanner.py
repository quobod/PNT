import nmap
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.TypeTester import (
    arg_is_a_string,
)

custom = cms["custom"]

""" 
    Connects to given host at the given port to deteremine whether the host is up and state of the port.
    @Param host String: IP address or range 
    @Param port Striing: The connection port or port range
"""


def is_port_open(host=None, port=None):
    nm_scanner = None

    if not arg_is_a_string(host):
        msg = "[{}] must be a string, but received a {}".format(host, type(host))
        cmsg = custom(255, 100, 100, msg)
        emsg = custom(255, 255, 255, "Invalid Argument: {}".format(host))
        message = "{}\t{}".format(emsg, cmsg)

        raise ValueError(message)

    elif not arg_is_a_string(port):
        msg = "[{}] must be a string, but received a {}".format(port, type(port))
        cmsg = custom(255, 100, 100, msg)
        emsg = custom(255, 255, 255, "Invalid Argument: {}".format(port))
        message = "{}\t{}".format(emsg, cmsg)

        raise ValueError(message)

    elif not host == None and not port == None:
        nm_scanner = nmap.PortScanner()

        nm_scanner.scan(str(host), str(port))

        return nm_scanner
    else:
        message = "Expecting host and port arguments but received Host: {} and Port: {}".format(
            host, port
        )
        raise ValueError(message)
