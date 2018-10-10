import re
import logging

from ipaddress import IPv4Network

from nmap import PortScanner
from cpe import CPE
from pynetbox import api
from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import AuthenticationException
from paramiko.ssh_exception import SSHException
from paramiko.ssh_exception import NoValidConnectionsError


logging.getLogger('paramiko').setLevel(logging.CRITICAL)  # paramiko is noisy


class NetBoxScanner(object):
    
    def __init__(self, address, token, tls_verify, nmap_args, devs_auth, tag, unknown):
        self.netbox = api(address, token=token, ssl_verify=tls_verify)
        self.nmap_args = nmap_args
        self.devs = devs_auth
        self.tag = tag
        self.unknown = unknown
        self.stats = {'created':0, 'updated':0, 'deleted':0,
            'undiscovered':0, 'duplicated':0}
    
    def parser(self, networks):
        '''Parses a list of networks in CIDR notation.

        :param networks: a list of networks like ['10.0.0.0/8',...]
        :return: False if parsing is OK, or a string with duplicated
        or mistyped networks.
        '''
        ipv4 = re.compile(r'^((2([0-4][0-9]|5[0-5])|1?[0-9]?[0-9])\.){3}(2([0-4][0-9]|5[0-5])|1?[0-9]?[0-9])\/(3[012]|[12]?[0-9])$')
        duplicated = set([x for x in networks if networks.count(x)>1])
        if duplicated:
            return ', '.join(duplicated)
        for net in networks:
            if not re.match(ipv4, net):
                return net
        return False

    def get_networks(self):
        '''Retrieves all networks/prefixes recorded into NetBox.'''
        return [str(net) for net in self.netbox.ipam.prefixes.all()]
    
    def get_description(self, address, name, cpe):
        '''Define a description based on hostname and CPE'''
        if name:
            return name
        else:
            c = CPE(cpe[0], CPE.VERSION_2_3)
            vendor = c.get_vendor()[0].upper()
            if vendor in self.devs:
                try:
                    client = SSHClient()
                    client.set_missing_host_key_policy(AutoAddPolicy())
                    client.connect(address, username=self.devs[vendor]['USER'], 
                        password=self.devs[vendor]['PASSWORD'])
                    stdin, stdout, stderr = client.exec_command(self.devs[vendor]['COMMAND'])
                    return '{}:{}'.format(vendor.lower(),
                        re.search(self.devs[vendor]['REGEX'], 
                        str(stdout.read().decode('utf-8'))).group(self.devs[vendor]['REGROUP']))
                except (AuthenticationException, SSHException, 
                    NoValidConnectionsError, TimeoutError, 
                    ConnectionResetError):
                    pass  
            return '{}.{}.{}'.format(c.get_vendor()[0], c.get_product()[0], 
                c.get_version()[0])
    
    def scan(self, network):
        '''Scan a network.
        
        :param network: a valid network, like 10.0.0.0/8
        :return: a list of tuples like [('10.0.0.1','Gateway'),...].
        '''
        hosts = []
        nm = PortScanner()
        nm.scan(network, arguments=self.nmap_args)

        for host in nm.all_hosts():
            address = nm[host]['addresses']['ipv4']
            try:
                description = self.get_description(
                    address, nm[host]['hostnames'][0]['name'], 
                    nm[host]['osmatch'][0]['osclass'][0]['cpe'])
            except (KeyError, AttributeError, IndexError, 
                NotImplementedError):
                description = self.unknown
            hosts.append((address, description))
        return hosts

    def logger(self, logtype, **kwargs):
        '''Logs and updates stats for NetBox interactions.'''
        if logtype == 'scanned':
            logging.info('scanned: {} ({} hosts discovered)'.format(kwargs['net'], kwargs['hosts']))
        elif logtype == 'created':
            logging.info('created: {}/32 "{}"'.format(kwargs['address'], 
                kwargs['description']))
            self.stats['created'] += 1
        elif logtype == 'updated':
            logging.warning('updated: {}/32 "{}" -> "{}"'.format(
                kwargs['address'], kwargs['description_old'], 
                kwargs['description_new']))
            self.stats['updated'] += 1
        elif logtype == 'deleted':
            logging.warning('deleted: {} "{}"'.format(kwargs['address'], 
                kwargs['description']))
            self.stats['deleted'] += 1
        elif logtype == 'undiscovered':
            logging.warning('undiscovered: {} "{}"'.format(kwargs['address'], 
                kwargs['description']))
            self.stats['undiscovered'] += 1
        elif logtype == 'duplicated':
            logging.error('duplicated: {}/32'.format(kwargs['address']))
            self.stats['duplicated'] += 1
        elif logtype == 'mistyped':
            logging.error('mistyped: {}'.format(kwargs['badnets']))

    def sync_host(self, host):
        '''Syncs a single host to NetBox.

        :param host: a tuple like ('10.0.0.1','Gateway')
        :return: True if syncing is ok or False in other case.
        '''
        try:
            nbhost = self.netbox.ipam.ip_addresses.get(address=host[0])
        except ValueError:
            self.logger('duplicated', address=host[0])
            return False
        if nbhost:
            if (self.tag in nbhost.tags) and (host[1] != nbhost.description):
                aux = nbhost.description
                nbhost.description = host[1]
                nbhost.save()
                self.logger('updated', address=host[0], description_old=aux, 
                    description_new=host[1])
        else:
            self.netbox.ipam.ip_addresses.create(address=host[0], 
                tags=[self.tag], description=host[1])
            self.logger('created', address=host[0], description=host[1])
        return True

    def sync(self, networks):
        '''Scan some networks and sync them to NetBox.

        :param networks: a list of valid networks, like ['10.0.0.0/8']
        :return: synching statistics
        '''
        for s in self.stats:
            self.stats[s] = 0
        
        parsing = self.parser(networks)
        if parsing:
            self.logger('mistyped', badnets=parsing)
            return False

        for net in networks:
            hosts = self.scan(net)
            self.logger('scanned', net=net, hosts=len(hosts))
            for host in hosts:
                self.sync_host(host)       
            for ipv4 in IPv4Network(net):  # cleanup
                address = str(ipv4)
                if not any(h[0]==address for h in hosts):
                    try:
                        nbhost = self.netbox.ipam.ip_addresses.get(address=address)
                        if self.tag in nbhost.tags:
                            nbhost.delete()
                            self.logger('deleted', address=nbhost.address, 
                                description=nbhost.description)
                        else:
                            self.logger('undiscovered', address=nbhost.address, 
                                description=nbhost.description)
                    except (AttributeError, ValueError):
                        pass
        return True
