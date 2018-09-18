from netscan import NetworkScanner
from nbsync import NetBoxSync
from config import NETBOX, DISABLE_TLS_WARNINGS, TARGETS

from datetime import datetime

print('{} - starting scan'.format(datetime.now()))
ns = NetworkScanner()
ns.scan(TARGETS)

print('{} - starting sync'.format(datetime.now()))
nbs = NetBoxSync(NETBOX['ADDRESS'], NETBOX['TLS'], NETBOX['TOKEN'], 
    NETBOX['PORT'], DISABLE_TLS_WARNINGS)
nbs.sync()

print('{} - finished'.format(datetime.now()))
exit(0)
