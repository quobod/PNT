import socket, subprocess, sys
from datetime import datetime


class PortScanner:
    __default_range = range(0, 65535, 1)
    __remote_server = None
    __remote_server_ip = None
    __host_open_ports = {}
    __open_ports = []

    def __init__(self) -> None:
        pass

    def set_remote_server(self, rs):
        self.__remote_server = rs
        self.__remote_server_ip = socket.gethostbyname(self.__remote_server)

    def set_range(self, range):
        self.__default_range = range

    def set_range_start_and_end(self, start, end, step=1):
        if not start == None and not end == None:
            self.__default_range = range(start, end, step)

    def get_remote_server(self):
        return self.__remote_server

    def get_range(self):
        return self.__default_range

    def get_open_ports(self):
        return self.__host_open_ports

    def get_open_ports_count(self):
        return len(self.__host_open_ports)

    def scan_tcp_ports(self):
        self.__host_open_ports.clear()
        list = []
        self.__host_open_ports.update({str(self.__remote_server_ip): list})

        # Clear screen
        subprocess.call("clear", shell=True)

        # Print a nice banner
        decor = "-"
        print(decor * 60)
        print("Please wait, scanning remote host {}".format(self.__remote_server_ip))
        print(decor * 60)

        t1 = datetime.now()

        try:
            for port in self.__default_range:
                # print("Scanning port: {}".format(port))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((self.__remote_server_ip, port))

                if result == 0:
                    list.append(str(port))
                    # print("Port {} Open".format(port))
                sock.close()

        except KeyboardInterrupt as kbi:
            print("\n\nYou killed the scanning")
            sys.exit()

        except socket.gaierror as sge:
            print("\n\nHostname {} could not be resolved".format(self.__remote_server))
            sys.exit()

        except socket.error as se:
            print("\n\nCould not connect to {}".format(self.__remote_server_ip))
            sys.exit()

        except TypeError as te:
            print("\n\nExpecting a tuple {}".format(te))
            sys.exit()

        t2 = datetime.now()

        total_time = t2 - t1

        print("Scanning completed in {}".format(total_time))

    def scan_tcp_ports_verbose(self):
        self.__host_open_ports.clear()
        list = []
        self.__host_open_ports.update({str(self.__remote_server_ip): list})

        # Clear screen
        subprocess.call("clear", shell=True)

        # Print a nice banner
        decor = "-"
        print(decor * 60)
        print("Please wait, scanning remote host {}".format(self.__remote_server_ip))
        print(decor * 60)

        t1 = datetime.now()

        try:
            for port in self.__default_range:
                print("Scanning port: {}".format(port))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((self.__remote_server_ip, port))

                if result == 0:
                    list.append(str(port))
                    print("Port {} Open".format(port))
                sock.close()

        except KeyboardInterrupt as kbi:
            print("\n\nYou killed the scanning")
            sys.exit()

        except socket.gaierror as sge:
            print("\n\nHostname {} could not be resolved".format(self.__remote_server))
            sys.exit()

        except socket.error as se:
            print("\n\nCould not connect to {}".format(self.__remote_server_ip))
            sys.exit()

        except TypeError as te:
            print("\n\nExpecting a tuple {}".format(te))
            sys.exit()

        t2 = datetime.now()

        total_time = t2 - t1

        print("Scanning completed in {}".format(total_time))

    def __to_string():
        return "Port Scanner"


port_scanner = PortScanner
