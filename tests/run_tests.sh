#!/bin/sh
#
# Before running these tests, you must define some
# environment variables, such as:
# 
# $ export NETBOX_ADDRESS="https..."
# $ export NETBOX_TOKEN="..."
# $ export NMAP_PATH="..."
##

python -m unittest tests.test_netbox
python -m unittest tests.test_nmap
