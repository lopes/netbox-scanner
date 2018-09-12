# netbox-scanner configuration file.

NETBOX = {
    'ADDRESS': '',
    'TOKEN': '',
    'TLS': True,
    'PORT': 443,
}

DATABASE = {
    'NAME': 'nbscanner',    # database name
    'USER': 'nbscanner',    # postgresql user
    'PASSWORD': 'abc123',   # postgresql password
    'HOST': 'localhost',    # database server
    'PORT': '5432',         # database port
}

SESSION_LENGTH = 16  # length of scan's session token
DISABLE_TLS_WARNINGS = True  # should urllib stop displaying TLS/SSL warnings?

# These are the targets to be scanned.  It could be:
# - single hosts: 10.2.50.7
# - single networks: 10.2.50.0/24
# - some hosts: 10.2.50.1-7
# The syntax is just the same as used in Nmap.
# Example: ['10.2.50.7', '10.2.50.0/24']
TARGETS = []
