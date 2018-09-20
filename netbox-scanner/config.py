# netbox-scanner configuration file.

NETBOX = {
    'ADDRESS': '',
    'TOKEN': '',
    'TLS': True,
    'PORT': 443,
}

TAG = 'auto'
UNKNOWN_HOSTNAME = 'UNKNOWN HOST'
DISABLE_TLS_WARNINGS = True  # stop displaying TLS/SSL warnings?

# These are the targets to be scanned.
# Example: ['192.168.40.0/20', '10.2.50.0/24']
TARGETS = []
