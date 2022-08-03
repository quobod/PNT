from argparse import ArgumentError
from genericpath import isfile
import os
import re
import time
import qrcode
from custom_modules.PatternConstants import FILE_EXTENSION


def generate_qr_code():
    url = input("Web address or plain text\t\t")

    print("Name the output file without extension")

    name = input("Output>\t")

    # If name ends with ".abc" then raise an error

    qr = qrcode.QRCode(5, error_correction=qrcode.ERROR_CORRECT_L)

    qr.add_data(url)
    qr.make()

    im = qr.make_image()

    time.sleep(1)

    qr_img_path = os.path.join(name + ".png")

    if os.path.isfile(qr_img_path):
        os.remove(qr_img_path)

    im.save(qr_img_path, format="png")
    print("QR code generated\n")
