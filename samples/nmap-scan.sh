#!/bin/sh
#
# This is just an example.
#
# Since scanning many networks can produce huge XML files,
# the idea is to create one XML file per network, then
# use all of them as input to nbs.nmap.Nmap().
#
# If you scan few networks with few hosts or if you just
# want to experiment, feel free to use the `-iL` option of
# Nmap, passing a list of all networks and hosts to be
# scanned.
#
# For the purpose of this example, assume that netbox-scanner
# is configured to use the same directory of this script
# to look for XML files.
##

NETWORKS="192.168.252.0/24 192.168.3.0/24"
TODAY="$(date +%d.%m.%yT%H:%M:%S%Z)"

for net in $NETWORKS; do
    NETNAME=$(echo $net | tr -s '/' '-')
    #nmap "$net" -T4 -O -F --host-timeout 30s -oX nmap-"$NETNAME".xml
    nmap "$net" -T4 -sn --host-timeout 30s -oX nmap-"$NETNAME".xml
done

python netbox-scanner.py nmap
tar -czvf scans/nmap-"$TODAY".tar.gz *.xml
rm -rf *.xml
