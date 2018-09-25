#!/usr/bin/env python3

import logging
from sys import stdout, stderr
from argparse import ArgumentParser
from datetime import datetime
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

import config
from nbscan import NetBoxScanner


argp = ArgumentParser()
argp.add_argument('-l', '--log', help='logfile path', default=config.LOG)
argp.add_argument('-a', '--address', help='netbox address', 
    default=config.NETBOX['ADDRESS'])
argp.add_argument('-t', '--token', help='netbox access token', 
    default=config.NETBOX['TOKEN'])
argp.add_argument('-v', '--verify', help='tls verify', 
    action='store_true', default=config.NETBOX['TLS_VERIFY'])
argp.add_argument('-g', '--tag', help='netbox-scanner tag', 
    default=config.TAG)
argp.add_argument('-u', '--unknown', help='netbox-scanner unknown host', 
    default=config.UNKNOWN)
argp.add_argument('-n', '--networks', nargs='+', help='networks to be scanned',
    default=config.NETWORKS)
args = argp.parse_args()

logging.basicConfig(filename='{}/netbox-scanner-{}.log'.format(args.log,
    datetime.now().strftime('%Y%m%dT%H%M%SZ')),
    level=logging.INFO, 
    format='%(asctime)s\tnetbox-scanner\t%(levelname)s\t%(message)s')

disable_warnings(InsecureRequestWarning)

nbs = NetBoxScanner(args.address, args.token, args.verify, args.tag, args.unknown)
logging.info('started: {} networks'.format(len(args.networks)))
stats = nbs.sync(args.networks)
logging.info('finished: +{} ~{} -{} ?{} !{}'.format(stats[0], stats[1], 
    stats[2], stats[3], stats[4]))

exit(0)
