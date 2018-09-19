
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from ipaddress import IPv4Network

from nmap import PortScanner
from cpe import CPE
from netbox import NetBox

from config import TAGS, UNKNOWN_HOSTNAME


class NetBoxScanner(object):
    
    def __init__(self, host, tls, token, port, warnings=True):
        self.netbox = NetBox(host=host, use_ssl=tls, auth_token=token,
            port=port)
        if warnings:
            disable_warnings(InsecureRequestWarning)
    
    def get_description(self, name, cpe):
        if name:
            return name
        else:
            c = CPE(cpe[0], CPE.VERSION_2_3)
            return '{}.{}.{}'.format(c.get_vendor()[0], 
                c.get_product()[0], c.get_version()[0])
            
    def scan(self, network):
        ''''''
        hosts = []
        nm = PortScanner()
        nm.scan(network, arguments='-T4 -O -F')

        for host in nm.all_hosts():
            address = nm[host]['addresses']['ipv4']
            try:
                description = self.get_description(nm[host]['hostnames'][0]['name'], 
                    nm[host]['osmatch'][0]['osclass'][0]['cpe'])
            except (KeyError, AttributeError):
                description = UNKNOWN_HOSTNAME
            hosts.append({'address':address,'description':description})
        return hosts
    
    def sync(self, networks):
        for net in networks:
            hosts = self.scan(net)
            for host in hosts:
                nbhost = self.netbox.ipam.get_ip_addresses(address=host['address'])
                if nbhost:
                    if (TAGS[0] in nbhost[0]['tags']) and (host['description'] != nbhost[0]['description']):
                        self.netbox.ipam.update_ip('{}/32'.format(host['address']), description=host['description'])
                else:
                    self.netbox.ipam.create_ip_address('{}/32'.format(host['address']), tags=TAGS, description=host['description'])
            
            for ipv4 in IPv4Network(net):
                address = str(ipv4)
                if not any(h['address'] == address for h in hosts):
                    nbhost = self.netbox.ipam.get_ip_addresses(address=address)
                    try:
                        if TAGS[0] in nbhost[0]['tags']:
                            self.netbox.ipam.delete_ip_address(address)
                    except IndexError:
                        pass
