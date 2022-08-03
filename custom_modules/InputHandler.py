from glob import glob
import sys
import os
import subprocess
from .ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms

global start_action
cus = cms["custom"]


def init(msg="Enter the start message\t"):
    if not msg == None:
        msg += "\t"
        start_action = input(msg)
    else:
        cmsg = cus(245, 250, 202, "Warning\n" + "-" * 35)
        print(" " * 14 + "{}".format(cmsg))

        cmsg = cus(245, 245, 245, "Expecting a single string argument")
        print("{}\n".format(cmsg))
