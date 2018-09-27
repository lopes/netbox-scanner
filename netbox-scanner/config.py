# netbox-scanner configuration file.

TAG = 'auto'
UNKNOWN = 'UNKNOWN HOST'
LOG = '.'  # path to logfile

NETBOX = {
    'ADDRESS': 'https://',
    'TOKEN': '',
    'TLS_VERIFY': True
}

DEVICE_AUTH = {
    'CISCO': {
        'USER': '', 
        'PASSWORD': '',
        'COMMAND': 'show run | inc hostname'
    }
}

# These are the networks to be scanned.
# Example: ['192.168.40.0/20', '10.2.50.0/24']
NETWORKS = []
