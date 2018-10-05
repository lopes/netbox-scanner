#!/usr/bin/env python3

import logging
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
argp.add_argument('-m', '--nmap', help='set Nmap arguments', 
    default=config.NMAP_ARGS)
argp.add_argument('-d', '--devices', help='device authentication crendentials',
    default=config.DEVICE_AUTH)
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

nbs = NetBoxScanner(args.address, args.token, args.verify, args.nmap, 
    args.devices, args.tag, args.unknown)
logging.info('started: {} networks'.format(len(args.networks)))
nbs.sync(args.networks)
logging.info('finished: +{} ~{} -{} ?{} !{}'.format(nbs.stats['created'], 
    nbs.stats['updated'], nbs.stats['deleted'], nbs.stats['undiscovered'], 
    nbs.stats['duplicated']))

exit(0)
