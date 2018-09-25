# netbox-scanner configuration file.

NETBOX = {
    'ADDRESS': '',
    'TOKEN': '',
    'TLS_VERIFY': True
}

TAG = 'auto'
UNKNOWN = 'UNKNOWN HOST'
LOG = '.'  # path to logfile

# These are the networks to be scanned.
# Example: ['192.168.40.0/20', '10.2.50.0/24']
NETWORKS = []
