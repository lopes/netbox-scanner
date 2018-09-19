#!/usr/bin/env python3

from logging import getLogger
from logging.config import dictConfig

import config
from nbscan import NetBoxScanner

dictConfig(config.LOGGING_CONFIG)
logger = getLogger('netbox-scanner')

nbs = NetBoxScanner(config.NETBOX['ADDRESS'], config.NETBOX['TLS'], 
    config.NETBOX['TOKEN'], config.NETBOX['PORT'], config.TAG, 
    config.UNKNOWN_HOSTNAME, config.DISABLE_TLS_WARNINGS)

logger.debug('starting')
nbs.sync(config.TARGETS)
logger.debug('finished')

exit(0)
1975107045