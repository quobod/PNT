#! /usr/bin/python3

import unittest
import sys
import re
from custom_modules.NmapPortScanner import is_port_open as ipo
from custom_modules.ArgumentManager import filtered, filtered_count
from custom_modules.PatternConstants import FILE_EXTENSION as fe

TITLE = "NmapPortScanner tests"

host = "192.168.1.1"
port = "631"
ports = "1-1001"
verbose = True
report = True
timeout = 2


def dummy(a, b):  # defining the function to be tested
    return a * b


class Tests(unittest.TestCase):  # creating the class
    def test_dummy(self):  # method that tests the function
        self.assertEqual(
            dummy(4, -2), -8
        )  # testing by calling the function and passing the predicted result


class TestIsPortOpenMethod(unittest.TestCase):
    def test_return_not_none(self):
        self.assertIsNotNone(ipo(host, port, verbose, timeout, report))

    def test_raise_argument_error(self):
        self.assertRaises(ValueError, ipo, None, None, verbose, timeout, report)
        self.assertRaises(ValueError, ipo, host, None, verbose, timeout, report)
        self.assertRaises(ValueError, ipo, None, port, verbose, timeout, report)

    def test_return_object(self):
        results = ipo(host, port, verbose, timeout, report)

        # Print hosts
        for i, h in enumerate(results.all_hosts()):
            print("{}.\t{}".format(i, h))

        # Print host names
        for i, h in enumerate(results.all_hosts()):
            print("{}.\tHost: {}\tName: {}".format(i, h, results[h].hostname()))


if __name__ == "__main__":
    unittest.main()
