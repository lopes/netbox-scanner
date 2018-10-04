# netbox-scanner configuration file.

TAG = 'auto'
UNKNOWN = 'UNKNOWN HOST'
LOG = '.'  # path to logfile
NMAP_ARGS = '-T4 -O -F --host-timeout 30s'

NETBOX = {
    'ADDRESS': 'https://',
    'TOKEN': '',
    'TLS_VERIFY': True
}

DEVICE_AUTH = {
    # 'CISCO': {
    #     'USER': 'netbox', 
    #     'PASSWORD': '',
    #     'COMMAND': 'show run | inc hostname',
    #     'REGEX': r'hostname ([A-Z|a-z|0-9|\-|_]+)',
    #     'REGROUP': 1
    # }
}

# These are the networks to be scanned.
# Example: ['192.168.40.0/20', '10.2.50.0/24']
NETWORKS = []
