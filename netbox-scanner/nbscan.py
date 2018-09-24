import logging
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from ipaddress import IPv4Network

from nmap import PortScanner
from cpe import CPE
from netbox import NetBox


class NetBoxScanner(object):
    
    def __init__(self, host, tls, token, port, tag, unknown, warnings=True):
        self.netbox = NetBox(host=host, use_ssl=tls, auth_token=token,
            port=port)
        self.tag = tag
        self.unknown = unknown
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
        '''Scan a network.
        
        :param network: a valid network, like 10.0.0.0/8
        :return: a list with dictionaries of responsive 
        hosts (addr and description)
        '''
        hosts = []
        nm = PortScanner()
        nm.scan(network, arguments='-T4 -O -F')

        for host in nm.all_hosts():
            address = nm[host]['addresses']['ipv4']
            try:
                description = self.get_description(
                    nm[host]['hostnames'][0]['name'], 
                    nm[host]['osmatch'][0]['osclass'][0]['cpe'])
            except (KeyError, AttributeError, IndexError):
                description = self.unknown
            hosts.append({'address':address,'description':description})
        return hosts
    
    def sync(self, networks):
        '''Scan some networks and sync them to NetBox.

        :param networks: a list of valid networks, like ['10.0.0.0/8']
        :return: nothing will be returned
        '''
        for net in networks:
            logging.info('scan: {}'.format(net))
            hosts = self.scan(net)
            for host in hosts:
                nbhost = self.netbox.ipam.get_ip_addresses(
                    address=host['address'])
                if nbhost:
                    if (self.tag in nbhost[0]['tags']) and (
                        host['description'] != nbhost[0]['description']):
                        logging.warning('update: {} "{}" -> "{}"'.format(
                            host['address'], nbhost[0]['description'],
                            host['description']))
                        self.netbox.ipam.update_ip('{}/32'.format(
                            host['address']), description=host['description'])
                else:
                    logging.info('create: {} "{}"'.format(host['address'], 
                        host['description']))
                    self.netbox.ipam.create_ip_address(
                        '{}/32'.format(host['address']), 
                        tags=[self.tag], description=host['description'])
            
            for ipv4 in IPv4Network(net):
                address = str(ipv4)
                if not any(h['address'] == address for h in hosts):
                    nbhost = self.netbox.ipam.get_ip_addresses(
                        address=address)
                    try:
                        if self.tag in nbhost[0]['tags']:
                            logging.warning('delete: {} "{}"'.format(
                                nbhost[0]['address'], 
                                nbhost[0]['description']))
                            self.netbox.ipam.delete_ip_address(address)
                        else:
                            logging.info('undiscovered: {}'.format(
                                nbhost[0]['address']))
                    except IndexError:
                        pass
