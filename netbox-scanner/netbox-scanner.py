#!/usr/bin/env python3

import logging
import logging.handlers as handlers

import config
from nbscan import NetBoxScanner


logger = logging.getLogger('netbox-scanner')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')
loghandler = handlers.TimedRotatingFileHandler('netbox-scanner.log', when='M', interval=1, backupCount=2)
loghandler.setLevel(logging.INFO)
loghandler.setFormatter(formatter)
logger.addHandler(loghandler)

nbs = NetBoxScanner(config.NETBOX['ADDRESS'], config.NETBOX['TLS'], 
    config.NETBOX['TOKEN'], config.NETBOX['PORT'], config.TAG, 
    config.UNKNOWN_HOSTNAME, config.DISABLE_TLS_WARNINGS)

logger.info('starting')
nbs.sync(config.TARGETS)
logger.info('finished')

exit(0)
