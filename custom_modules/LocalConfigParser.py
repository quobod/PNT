#! /usr/bin/python3

from scapy.all import *

""" 
    Returns local network interface name
    It's IP address and the gateway address
"""


# Return 3 strings
def return_route():
    return (
        conf.route.route()[0],
        conf.route.route()[1],
        conf.route.route()[2],
    )


# Return tuple
def return_local_route():
    return conf.route.route()


# Arp request
def return_arp_results(
    target=None, timeout=None, cache=None, verbose=None, report=None
):

    # print("{}  {}  {}  {}  {}".format(target, timeout, cache, verbose, report))
    global _timeout, _verbose, _report, _cache, _target

    _timeout = 2
    _verbose = False
    _report = False
    _cache = False
    _target = "192.168.1.0/24"

    if not target == None:
        _target = target

        if not timeout == None:
            _timeout = timeout

        if not cache == None and str(type(cache)) == "<class 'bool'>":
            _cache = cache

        if not verbose == None and str(type(verbose)) == "<class 'bool'>":
            _verbose = verbose

        if not report == None and str(type(report)) == "<class 'bool'>":
            _report = report

        # if _cache == True:
        #     print("cache")

        # if _verbose == True:
        #     print("verbose")

        # if _report == True:
        #     print("report")

        results = arping(_target, _timeout, _cache, _verbose)[0]

        print("\n")

        for sent, recv in results:
            """if _verbose:
            print(
                "From {}\t{}\nTo {}\t\t{}\n".format(
                    str(sent.psrc).strip(),
                    str(sent.hwsrc).strip(),
                    str(recv.psrc).strip(),
                    str(recv.hwsrc).strip(),
                )
            )"""

            if _report:
                arp_results = "_arp-results.txt"
                address_map = "{}\t{}\n".format(recv.psrc, recv.hwsrc)
                address_map_bytes = bytes(address_map, "utf-8")

                with open(arp_results, "ab") as file:
                    file.write(address_map_bytes)


# Get gateway address
def return_gateway_addr():
    return conf.route.route(get_if_addr(conf.iface[1]))[2]


# Get local IP address
def return_local_ip_address():
    return get_if_addr(conf.iface)


# Get local IP address by name
def return_local_ip_address_by_name(name=conf.iface):
    return get_if_addr(name)


# Get local MAC address
def return_local_mac_address():
    return get_if_hwaddr(conf.iface)


# Get local MAC address by iface name
def return_local_mac_address_by_iface_name(name=conf.iface):
    return get_if_hwaddr(name)


# Get MAC by IP address
def return_mac_by_ip_address(ip=get_if_addr(conf.iface)):
    return getmacbyip(ip)
