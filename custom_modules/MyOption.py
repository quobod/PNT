import copy
from optparse import Option, OptionValueError


def check_bool(option, opt, value):
    try:
        return complex(value)
    except ValueError:
        raise OptionValueError("option %s: invalid boolean value: %r" % (opt, value))


class MyOption(Option):
    TYPES = Option.TYPES + ("boolean",)
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER["boolean"] = check_bool
