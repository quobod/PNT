from custom_modules.PlatformConstants import LINE_SEP
from custom_modules.TypeTester import (
    arg_is_a_dict,
    arg_is_a_list,
    arg_is_a_string,
    arg_is_a_tuple,
    arg_is_an_int,
)


def print_this(_tuple):
    for t in _tuple:
        if arg_is_a_dict(t):
            for k, v in t.items():
                print("{}:\t{}".format(k, v))
        elif arg_is_a_string(t):
            print("{}.\t{}{}".format(t, LINE_SEP, LINE_SEP))
