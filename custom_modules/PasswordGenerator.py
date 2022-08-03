import string
from random import *


def generate_password():
    character = (
        string.ascii_letters
        + string.digits
        + string.ascii_uppercase
        + string.punctuation
        + string.ascii_lowercase
    )

    password = "".join(choice(character) for x in range(randint(1, 14)))

    return password
