import logging
from ipaddress import IPv4Network

from nmap import PortScanner
from cpe import CPE
from pynetbox import api


class NetBoxScanner(object):
    
    def __init__(self, address, token, tls_verify, tag, unknown):
        self.netbox = api(address, token=token, ssl_verify=tls_verify)
        self.tag = tag
        self.unknown = unknown
    
    def get_description(self, name, cpe):
        '''Define a description based on hostname and CPE'''
        if name:
            return name
        else:
            c = CPE(cpe[0], CPE.VERSION_2_3)
            return '{}.{}.{}'.format(c.get_vendor()[0], 
                c.get_product()[0], c.get_version()[0])
    
    def nbhandler(self, command, **kwargs):
        '''Handles NetBox integration'''
        if command == 'get':
            return self.netbox.ipam.ip_addresses.get(
                address=kwargs['address'])
        elif command == 'create':
            self.netbox.ipam.ip_addresses.create(address=kwargs['address'], 
                tags=kwargs['tag'], description=kwargs['description'])
        elif command == 'update':
            kwargs['nbhost'].description = kwargs['description']
            kwargs['nbhost'].save()
        elif command == 'delete':
            kwargs['nbhost'].delete()
        else:
            raise AttributeError
            
    def scan(self, network):
        '''Scan a network.
        
        :param network: a valid network, like 10.0.0.0/8
        :return: a list with dictionaries of responsive 
        hosts (address and description)
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
        :return: synching statistics are returned as a tuple
        '''
        create = update = delete = undiscovered = duplicate = 0
        for net in networks:
            hosts = self.scan(net)
            logging.info('scan: {} ({} hosts discovered)'.format(net, len(hosts)))
            for host in hosts:
                try:
                    nbhost = self.nbhandler('get', address=host['address'])
                except ValueError:
                    logging.error('duplicate: {}/32'.format(host['address']))
                    duplicate += 1
                    continue
                if nbhost:
                    if (self.tag in nbhost.tags) and (
                        host['description'] != nbhost.description):
                        logging.warning('update: {} "{}" -> "{}"'.format(
                            str(nbhost.address), nbhost.description, 
                            host['description']))
                        self.nbhandler('update', nbhost=nbhost, 
                            description=host['description'])
                        update += 1
                else:
                    logging.info('create: {}/32 "{}"'.format(host['address'], 
                        host['description']))
                    self.netbox.ipam.ip_addresses.create(
                        address=host['address'], tags=[self.tag], 
                        description=host['description'])
                    create += 1
            
            for ipv4 in IPv4Network(net):
                address = str(ipv4)
                if not any(h['address'] == address for h in hosts):
                    nbhost = self.nbhandler('get', address=address)
                    try:
                        if self.tag in nbhost.tags:
                            logging.warning('delete: {} "{}"'.format(
                                nbhost.address, nbhost.description))
                            self.nbhandler('delete', nbhost=nbhost)
                            delete += 1
                        else:
                            logging.warning('undiscovered: {} "{}"'.format(
                                nbhost.address, nbhost.description))
                            undiscovered += 1
                    except AttributeError:
                        pass
        return (create, update, delete, undiscovered, duplicate)
