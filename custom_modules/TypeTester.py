def arg_is_a_tuple(port_start_range):
    return (
        "<class 'tuple'>" == str(type(port_start_range))
        and not port_start_range == None
    )


def arg_is_an_int(port_start_range):
    return (
        "<class 'int'>" == str(type(port_start_range)) and not port_start_range == None
    )


def arg_is_a_string(port_start_range):
    return (
        "<class 'str'>" == str(type(port_start_range)) and not port_start_range == None
    )


def arg_is_a_dict(port_start_range):
    return (
        "<class 'dict'>" == str(type(port_start_range)) and not port_start_range == None
    )


def arg_is_a_list(port_start_range):
    return (
        "<class 'list'>" == str(type(port_start_range)) and not port_start_range == None
    )


def arg_is_a_float(port_start_range):
    return (
        "<class 'float'>" == str(type(port_start_range))
        and not port_start_range == None
    )
