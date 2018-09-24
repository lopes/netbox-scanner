#!/usr/bin/env python3

import logging
from sys import stdout, stderr
from argparse import ArgumentParser
from datetime import datetime

import config
from nbscan import NetBoxScanner


logging.basicConfig(filename='netbox-scanner-{}.log'.format(
    datetime.now().strftime('%Y%m%dT%H%M%SZ')),
    level=logging.INFO, 
    format='%(asctime)s\tnetbox-scanner\t%(levelname)s\t%(message)s')

argp = ArgumentParser()
argp.add_argument('-a', '--address', help='netbox address', 
    default=config.NETBOX['ADDRESS'])
argp.add_argument('-s', '--tls', help='netbox use tls', 
    action='store_true', default=config.NETBOX['TLS'])
argp.add_argument('-t', '--token', help='netbox access token', 
    default=config.NETBOX['TOKEN'])
argp.add_argument('-p', '--port', help='netbox access port', 
    default=config.NETBOX['PORT'])
argp.add_argument('-g', '--tag', help='netbox-scanner tag', 
    default=config.TAG)
argp.add_argument('-u', '--unknown', help='netbox-scanner unknown host', 
    default=config.UNKNOWN_HOSTNAME)
argp.add_argument('-w', '--warnings', help='disable tls warnings', 
    action='store_true', default=config.DISABLE_TLS_WARNINGS)
argp.add_argument('-n', '--networks', nargs='+', help='networks to be scanned',
    default=config.NETWORKS)
args = argp.parse_args()

nbs = NetBoxScanner(args.address, args.tls, args.token, args.port, 
    args.tag, args.unknown, args.warnings)
nbs.sync(args.networks)
logging.info('finished')

exit(0)
