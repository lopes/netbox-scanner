import re

from config import NETWORKS


def parser(networks):
    '''Parses a list of networks in CIDR notation.

    :param networks: a list of networks like ['10.0.0.0/8',...]
    :return: False if parsing is OK, or a string with duplicated
    or mistyped networks.
    '''
    ipv4 = re.compile(r'^((2([0-4][0-9]|5[0-5])|1?[0-9]?[0-9])\.){3}(2([0-4][0-9]|5[0-5])|1?[0-9]?[0-9])\/(3[012]|[12]?[0-9])$')
    duplicated = set([x for x in networks if networks.count(x)>1])
    if duplicated:
        return ', '.join(duplicated)
    for net in networks:
        if not re.match(ipv4, net):
            return net
    return False

nets = NETWORKS
nets.sort()

p = parser(nets)
if not p:
    print(nets)
else:
    print('ERROR: {}'.format(p))
