#! /usr/bin/python3

import sys
import re
from custom_modules.NmapPortScanner import scan_port
from custom_modules.ArgumentManager import filtered, filtered_count
from custom_modules.PatternConstants import FILE_EXTENSION as fe

if filtered_count > 0:
    pattern = re.compile(r"(.)+(\.[a-z]{2,3})")

    for arg in filtered:
        match = re.search(pattern, arg)

        if not match == None:
            print(match.group())
        else:
            print("\nNo Match for {}\n".format(arg))
