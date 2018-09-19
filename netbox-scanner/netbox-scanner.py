from nbscan import NetBoxScanner
from config import NETBOX, DISABLE_TLS_WARNINGS, TARGETS

from datetime import datetime

print('starting  - {}'.format(datetime.now()))
nbs = NetBoxScanner(NETBOX['ADDRESS'], NETBOX['TLS'], 
    NETBOX['TOKEN'], NETBOX['PORT'], DISABLE_TLS_WARNINGS)
nbs.sync(TARGETS)
print('finishing - {}'.format(datetime.now()))

exit(0)
