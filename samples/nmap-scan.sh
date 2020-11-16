#!/usr/bin/env bash
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

NETWORKS="10.1.2.3/24 10.2.3.4/32 192.168.0.0/19"
TODAY="$(date +%d%m%yT%H%M%S%Z)"

for net in $NETWORKS; do
  rawNet="${net:0:-3}"
  sudo nmap -T4 -O -F --host-timeout 30s -oX nmap-"$rawNet".xml "$net"
done

python ../netbox-scanner.py nmap
tar -czvf nmap-"$TODAY".tar.gz *.xml
rm -rf *.xml
