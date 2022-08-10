import re
import os
import time
import qrcode


def generate_qr_code(url=None, name=None):

    if not url == None and not name == None:

        # If name ends with ".abc" then raise an error
        FILE_EXTENSION = re.compile(r"(.)+(\.[a-z]{2,3})")
        ended_with_ext = re.search(FILE_EXTENSION, name)

        if not ended_with_ext == None:
            return {
                "status": False,
                "reason": "Name [{}] must not end with an extension (e.g. .xyz, .xy) etc".format(
                    name
                ),
            }

        qr = qrcode.QRCode(5, error_correction=qrcode.ERROR_CORRECT_L)

        qr.add_data(url)
        qr.make()

        im = qr.make_image()

        time.sleep(1)

        qr_img_path = os.path.join(name + ".png")

        if os.path.isfile(qr_img_path):
            os.remove(qr_img_path)

        im.save(qr_img_path, format="png")
        return {"status": True}
