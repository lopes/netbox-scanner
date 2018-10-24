#!/usr/bin/env python3

import logging

from configparser import ConfigParser
from os import fsync
from os.path import expanduser
from datetime import datetime
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from nbscan import NetBoxScanner


template = '''
[GENERAL]
tag       = auto
unknown   = unknown host
log       = .
nmap_args = -T4 -O -F --host-timeout 30s

[NETBOX]
address = https://
token = 
tls_verify = True

[TACACS]
user     = netbox
password = 
command  = show run | inc hostname
regex    = hostname ([A-Z|a-z|0-9|\-|_]+)
regroup  = 1

[SCAN]
networks = 10.1.2.3/24,10.2.3.4/24
'''
conffile = expanduser('~/.netbox-scanner.conf')

try:
    config = ConfigParser()
    config.read(conffile)
    general_conf = config['GENERAL']
    netbox_conf = config['NETBOX']
    networks = config['SCAN']['networks'].split(',')
    tacacs_conf = dict()
    for key in config['TACACS']:
        tacacs_conf[key] = config['TACACS'][key]
    tacacs_conf['regroup'] = int(tacacs_conf['regroup'])
except KeyError:
    with open(conffile,'w+') as f:
        f.write(template)
        fsync(f)
    print('Config file was created at {}'.format(conffile))
    print('Fill all fields before run the script again.')
    exit(1)

logfile = '{}/netbox-scanner-{}.log'.format(general_conf['log'],
    datetime.now().strftime('%Y%m%dT%H%M%SZ'))
logging.basicConfig(filename=logfile, level=logging.INFO, 
    format='%(asctime)s\tnetbox-scanner\t%(levelname)s\t%(message)s')
disable_warnings(InsecureRequestWarning)


if __name__ == '__main__':
    nbs = NetBoxScanner(netbox_conf['address'], netbox_conf['token'], 
        netbox_conf.getboolean('tls_verify'), general_conf['nmap_args'], 
        tacacs_conf, general_conf['tag'], general_conf['unknown'])
    nbs.sync(networks)
    exit(0)
