def get_format(item_type):
    """
    Create format string to represent crits types in TAXII service's multi choice boxes.
    :param item_type The type of object for which we need a format string
    """
    fmt = ""
    if item_type == 'Certificate': # Good
        fmt = "{0[filename]} - {0[md5]}"
    elif item_type == 'Domain': # Good
        fmt = "{0[domain]} - {0[analyst]}"
    elif item_type == 'Email': # needs to be reworked somehow...
        fmt = "{0[subject]} - {0[date]}"
    elif item_type == 'Indicator': # good
        fmt = "{0[ind_type]} - {0[value]}"
    elif item_type == 'IP': # good
        fmt = "{0[ip]} - {0[ip_type]}"
    elif item_type == 'PCAP': # good?
        fmt = "{0[filename]} - {0[md5]}"
    elif item_type == 'RawData': # good
        fmt = "{0[title]} ({0[data_type]})" # - tool: '{0[tool].name}'"
    elif item_type == 'Sample': # good
        fmt = "{0[filename]} - {0[md5]}"
    elif item_type == 'Event':
        fmt = "{0[title]} - {0[event_type]}"
    return fmt
