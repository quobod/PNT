#! /usr/bin/python3

from ast import Param
import socket

from paramiko import HostKeys  # for connecting
from .ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms


def is_port_open(host, port, verbose=False, timeout=None):
    _timeout = 2.2

    if not timeout == None and not timeout <= 0:
        _timeout = timeout

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(_timeout)
            s.connect((host, port))
            connected = s.connect_ex((host, port))

            if connected == 0:
                return True
            else:
                return False
        except Exception as ex:
            if verbose:
                line = ""
                if "class" in str(type(ex)):
                    if len(ex.args) > 1:
                        line = "{}".format(ex.args[1])
                    elif len(ex.args) == 1:
                        line = "{}".format(ex.args[0])
                else:
                    line = "{}".format(ex)

                print(line)

            return False
