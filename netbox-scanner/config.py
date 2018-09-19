# netbox-scanner configuration file.

from logging import DEBUG

NETBOX = {
    'ADDRESS': '',
    'TOKEN': '',
    'TLS': True,
    'PORT': 443,
}

LOGGING_CONFIG = dict(
    version = 1,
    formatters = {
        'f': {'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'}
    },
    handlers = {
        'h': {
            'class': 'logging.StreamHandler', 
            'formatter': 'f', 
            'level': DEBUG
        }
    },
    root = {'handlers': ['h'], 'level': DEBUG},
)

TAG = 'auto'
UNKNOWN_HOSTNAME = 'UNKNOWN HOST'
DISABLE_TLS_WARNINGS = True  # stop displaying TLS/SSL warnings?

# These are the targets to be scanned.
# Example: ['192.168.40.0/20', '10.2.50.0/24']
TARGETS = []
