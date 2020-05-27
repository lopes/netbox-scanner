#!/usr/bin/env python3

import logging

from configparser import ConfigParser
from argparse import ArgumentParser
from os.path import expanduser, isfile
from datetime import datetime
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from nbs import NetBoxScanner
from nbs.nmap import Nmap


local_config = expanduser('~/.netbox-scanner.conf')
global_config = '/opt/netbox/netbox-scanner.conf'
config = ConfigParser()

if isfile(local_config):
    config.read(local_config)
elif isfile(global_config):
    config.read(global_config)
else:
    raise FileNotFoundError('Configuration file was not found.')

netbox = config['NETBOX']
nmap = config['NMAP']
prime = config['PRIME']

parser = ArgumentParser(description='netbox-scanner')
subparsers = parser.add_subparsers(title='Commands', dest='command')
subparsers.required = True
argsp = subparsers.add_parser('nmap', help='Nmap module')
argsp = subparsers.add_parser('prime', help='Cisco Prime module')
args = parser.parse_args()

logfile = '{}/netbox-scanner-{}.log'.format(
    netbox['logs'],
    datetime.now().isoformat()
)
logging.basicConfig(
    filename=logfile, 
    level=logging.INFO, 
    format='%(asctime)s\tnetbox-scanner\t%(levelname)s\t%(message)s'
)
logging.getLogger().addHandler(logging.StreamHandler())

disable_warnings(InsecureRequestWarning)


def cmd_nmap():  # nmap handler
    h = Nmap(nmap['path'], nmap['unknown'])
    h.run()
    print(len(h.hosts));exit(0)
    scan = NetBoxScanner(
        netbox, 
        Nmap(nmap['path'], nmap['unknown']).run(), 
        nmap['tag'], 
        nmap.getboolean('cleanup')
    )
    scan.sync()

def cmd_prime():  # prime handler
    pass


if __name__ == '__main__':
    if args.command == 'nmap': cmd_nmap()
    elif args.command == 'prime': cmd_prime()
    exit(0)
