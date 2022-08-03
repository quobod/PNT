#! /usr/bin/python3

import socket  # for connecting
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms


def is_port_open(host, port, verbose=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(0.2)
            s.connect((host, port))
        except Exception as ex:
            if verbose:
                print("\t{}\n".format(ex))
            return False
    return True
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # try:
    #     s.connect((host, port))
    #     s.settimeout(10)
    # except:
    #     return False
    # else:
    #     return True
    # finally:
    #     s.close()
    #     s = None


# get the host from the user
# host = input("Enter the host:\t")
# iterate over ports, from 1 to 1024
# for port in range(1, 1025):
#     if is_port_open(host, port):
#         print(f"{GREEN}[+] {host}:{port} is open      {RESET}")
#     else:
#         print(f"{GRAY}[!] {host}:{port} is closed    {RESET}", end="\r")


def check_port(host, port_start_range, port_end_range, verbose=False):
    _host = "192.168.1.1"
    sport = 1
    eport = 1025

    print(" " * 55 + "Port Scanner\n" + "-" * 12 + "> Target: {}".format(host))

    if not host == None and not len(host) == 0:
        _host = host

    if (
        not port_end_range == None
        and not port_end_range == 0
        and not len(str(port_end_range)) == 0
    ):
        eport = port_end_range

    if (
        not port_start_range == None
        and not port_start_range == 0
        and not len(str(port_start_range)) == 0
    ):
        sport = port_start_range

    for port in range(sport, eport):
        if verbose:
            cus = cms["custom"]
            msg = "\n\nChecking port {}".format(port)
            vmsg = cus(222, 222, 222, msg)
            print("{}".format(vmsg))

            if is_port_open(_host, port, verbose):
                suc = cms["success"]
                msg = "Port {} is opened".format(port)
                smsg = suc(msg)
                print("{}".format(smsg))
            else:
                cus = cms["custom"]
                msg = "Port {} is closed".format(port)
                cmsg = cus(100, 100, 100, msg)
                print("{}".format(cmsg))
        else:
            if is_port_open(_host, port, verbose):
                suc = cms["success"]
                msg = "Port {} is opened".format(port)
                smsg = suc(msg)
                print("{}".format(smsg))
