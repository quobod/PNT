#! /usr/bin/python3

import argparse
from operator import is_
import os
import qrcode
from custom_modules.PlatformConstants import LINE_SEP as lsep, CUR_DIR as cdir
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_modules.FileOperator import delete_file, append_file
from custom_modules.QRCodeGenerator import generate_qr_code as generate

cus = cms["custom"]
msg = None
desc = "This program will generate a QR code image from the given text"
epil = "Generates a two dimensional Quick Response (QR) code  pictograph from any kind of data (e.g. binary, alphanumeric, or Kanji symbols) etc. The QR pictograph will be saved in the user's home directory."
vers = "%prog 0.1"
data = None
name = None
file = None
verbose = False
is_file = False


def error_handler(*args):
    cus = cms["custom"]
    arg = args[0]
    cargs = cus(254, 64, 4, arg)
    print("{}".format(cargs))
    os.system("exit")


parser = argparse.ArgumentParser(description=desc, epilog=epil)

parser.error = error_handler

parser.version = vers

""" group arguments  """

group = parser.add_mutually_exclusive_group()

# verbosity output
group.add_argument(
    "-v", "--verbose", help="Increase output verbosity", action="store_true"
)

""" positional arguments """

# capture the file or text input
parser.add_argument(
    "-d",
    "--data",
    help="The data can be a path to a file or text argument",
    dest="data",
)

# name the generated qr code image
parser.add_argument("-n", "--name", help="Name the generated QR image", dest="name")


args = parser.parse_args()


if args.data:
    data = args.data

if args.name:
    name = args.name

if args.verbose:
    verbose = True

if not data == None and not name == None:
    data_msg = ""
    exists = os.path.exists(data)
    isfile = os.path.isfile(data)

    if exists and isfile:
        is_file = True
        file = open(data, "rb")
        data_msg = cus(
            255, 180, 22, "Encoding file [{}] with name [{}]".format(data, name)
        )
    else:
        data_msg = cus(
            255, 180, 22, "Encoding data [{}] with name [{}]".format(data, name)
        )

    if verbose:
        print("{}".format(data_msg))
        msg = cus(255, 255, 255, "... generating the QR code pictograpy")
        print("{}".format(msg))

    if is_file:
        results = generate(file, name)
    else:
        results = generate(data, name)

    status = results["status"]

    if verbose:
        if status:
            msg = cus(200, 255, 200, "Successfully generated QR code image")
            print("{}".format(msg))
        else:
            status = cus(255, 10, 10, "Failed".strip())
            reason = cus(255, 255, 255, results["reason"])
            msg = "{}:\t{}".format(status, reason)
            print("{}".format(msg))
    else:
        if not status:
            status = cus(255, 10, 10, "Failed".strip())
            reason = cus(255, 255, 255, results["reason"])
            msg = "{}:\t{}".format(status, reason)
            print("{}".format(msg))
    os._exit(0)


if data == None:
    msg = cus(255, 190, 190, "Data cannot be empty")
    print(msg)

if name == None:
    msg = cus(255, 190, 190, "Name cannot be empty")
    print(msg)
