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
                if "class" in str(type(ex)):
                    if len(ex.args) > 1:
                        print("{}".format(ex.args[1]))
                    elif len(ex.args) == 1:
                        print("{}".format(ex.args[0]))
                # else:
                #     print("{}".format(ex))

            return False


""" Method checks argument validity and run calls to the is_port_open method accordingly
    @Param host 
    @Param port_start_range 
    @Param port_end_range 
    @Param verbose 
    @Param timeout 
"""


def check_port(
    host=None, port_start_range=None, port_end_range=None, verbose=False, timeout=None
):
    cmsg = cms["custom"]
    _host = None
    sport = None
    eport = None
    _verbose = False
    _timeout = 2.2
    _port_range = False

    if not host == None and not len(host) == 0:
        _host = host

    if "<class 'tuple'>" == str(type(port_start_range)) and len(port_start_range) == 2:
        sport = port_start_range[0]
        eport = port_start_range[1]
        _port_range = True
    else:
        _port_range = False
        if (
            not port_end_range == None
            and not port_end_range <= 0
            and not len(str(port_end_range)) == 0
        ):
            eport = port_end_range

        if (
            not port_start_range == None
            and not port_start_range <= 0
            and not len(str(port_start_range)) == 0
        ):
            sport = port_start_range

    if not verbose == None and verbose:
        _verbose = verbose

    if not timeout == None and not timeout <= 0:
        _timeout = timeout

    if _verbose:
        title = cmsg(255, 255, 255, "Port Scanner")
        chost = cmsg(190, 255, 255, _host)
        target = cmsg(200, 200, 255, "Target: {}".format(chost))
        asterisk = cmsg(255, 245, 100, "*")
        underscore = "*"

        prog_start(title, target, asterisk, underscore)

        if _port_range:
            scan_action((sport, eport))

            for port in range(sport, eport):
                cus = cms["custom"]
                msg = "Checking port {}".format(port)
                cmsg = cus(222, 222, 222, msg)
                print("{}".format(cmsg))

                if is_port_open(_host, port, _verbose, _timeout):
                    suc = cms["success"]
                    msg = "Port {} is opened".format(port)
                    smsg = suc(msg)
                    print("{}\n".format(smsg))
                else:
                    cus = cms["custom"]
                    msg = "Port {} is closed".format(port)
                    cmsg = cus(100, 100, 100, msg)
                    print("{}\n".format(cmsg))
        else:
            if sport:
                scan_action(sport)
                cus = cms["custom"]
                msg = "Checking port {}".format(sport)
                cmsg = cus(222, 222, 222, msg)
                print("{}".format(cmsg))

                if is_port_open(_host, sport, verbose, _timeout):
                    suc = cms["success"]
                    msg = "Port {} is opened".format(sport)
                    smsg = suc(msg)
                    print("{}\n".format(smsg))
                else:
                    cus = cms["custom"]
                    msg = "Port {} is closed".format(sport)
                    cmsg = cus(100, 100, 100, msg)
                    print("{}\n".format(cmsg))
    else:

        if _port_range:
            for port in range(sport, eport):
                if is_port_open(_host, port, _verbose, _timeout):
                    suc = cms["success"]
                    msg = "Port {} is opened".format(port)
                    smsg = suc(msg)
                    print("{}".format(smsg))
                else:
                    cus = cms["custom"]
                    msg = "Port {} is closed".format(port)
                    cmsg = cus(100, 100, 100, msg)
                    # print("{}".format(cmsg))
        else:
            if sport:
                if is_port_open(_host, sport, verbose, _timeout):
                    suc = cms["success"]
                    msg = "Port {} is opened".format(sport)
                    smsg = suc(msg)
                    print("{}".format(smsg))
                else:
                    cus = cms["custom"]
                    msg = "Port {} is closed".format(sport)
                    cmsg = cus(100, 100, 100, msg)


def prog_start(title, target, asterisk, underscore):
    print(underscore * 100)
    print(asterisk + " " * 38 + title + " " * 46 + asterisk)
    print(asterisk + " " * 35 + target + " " * 41 + asterisk)
    print("*" * 100 + "\n")
    # print("{}".format(cmsg))


def scan_action(arg):
    cus = cms["custom"]
    msg = None
    if "<class 'tuple'>" == str(type(arg)) or "<class 'list'>" == str(type(arg)):
        sport = arg[0]
        eport = arg[1]
        msg = "Ports {}-{}".format(sport, eport)
    else:
        msg = "Port {}".format(arg)
    print("{}\n".format(cus(255, 255, 255, msg)))
