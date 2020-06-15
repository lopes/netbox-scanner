#!/bin/sh
#
# Before running these tests, fill the environment variables
# below according to your setup.  If you don't want to
# hardcode this data, just be sure to exporting them in
# your shell.
##

export NETBOX_ADDRESS=""
export NETBOX_TOKEN=""

export NMAP_PATH=""

export PRIME_ADDRESS=""
export PRIME_USER=""
export PRIME_PASS=""

export NETXMS_ADDRESS=""
export NETXMS_USER=""
export NETXMS_PASS=""


python -m unittest tests.test_netbox
python -m unittest tests.test_nmap
python -m unittest tests.test_prime
python -m unittest tests.test_netxms
