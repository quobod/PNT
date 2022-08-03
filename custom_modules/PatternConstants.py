import re

""" IPs """

IPv4 = re.compile(r"([0-9]{1,3}\.){3}([0-9]{1,3})")

IPv4_network = re.compile(r"([0-9]{1,3}\.){3}([0-9]{1,3})/[1-9]{1,3}$")

IP4 = r"([0-9]{1,3}\.){3}([0-9]{1,3})"

""" File extensions """

FILE_EXTENSION = re.compile(r"(.)+(\.[a-z]{2,3})")
