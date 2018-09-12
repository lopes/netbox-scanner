from random import SystemRandom
from string import ascii_lowercase, digits
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from nmap import PortScanner
from netbox import NetBox
from netbox.exceptions import NotFoundException

from config import NETBOX, DATABASE, SESSION_LENGTH, DISABLE_TLS_WARNINGS, TARGETS


class NetBoxScanner(object):
    
    def __init__(self):
        self.netbox = NetBox(host=NETBOX['address'],
            use_ssl=NETBOX['TLS'], auth_token=NETBOX['TOKEN'],
            port=NETBOX['PORT'])
        self.networks = TARGETS
        self.results = None
        self.session = ''.join(SystemRandom().choice(ascii_lowercase + digits)
            for _ in range(SESSION_LENGTH))
        if DISABLE_TLS_WARNINGS:
            disable_warnings(InsecureRequestWarning)

    def scan(self):
        '''
        Return pattern:
        {
            'networks': [
                {
                    'network': '10.2.50.0/25',
                    'hosts': [
                        {
                            'address': '10.2.50.7',
                            'mac': 'ff:ff:ff:ff:ff:ff',
                            'vendor': 'Dell',
                            'name': 'hostname',
                            'osvendor': 'Microsoft',
                            'osfamily': 'Windows',
                            'cpe': []
                        }
                    ]
                }
            ]
        }
        '''
        self.results = {'networks':[]}
        for net in self.networks:
            nm = PortScanner()
            nm.scan(net, arguments='-T4 -O -F')
            hosts = []
            for host in nm.all_hosts():
                ipv4 = nm[host]['addresses']['ipv4']
                name = nm[host]['hostnames'][0]['name']
                try:
                    mac = nm[host]['addresses']['mac']
                    vendor = nm[host]['addresses']['vendor'][mac]
                except KeyError:
                    mac = vendor = '-' 
                try:
                    osvendor = nm[host]['osmatch'][0]['osclass'][0]['vendor']
                    osfamily = nm[host]['osmatch'][0]['osclass'][0]['osfamily']
                    cpe = nm[host]['osmatch'][0]['osclass'][0]['cpe']
                except (KeyError, IndexError):
                    osvendor = osfamily = cpe = '-'
                hosts.append({'address':ipv4,'mac':mac,'vendor':vendor,
                    'name':name,'osvendor':osvendor,'osfamily':osfamily,
                    'cpe':cpe})
            self.results['networks'].append({'network':net,'hosts':hosts})
        return self.results
    
    def nbquery(self, address):
        addr = self.netbox.ipam.get_ip_address(address)
        print(addr); return
        try:
            print(addr[0]['address'])
            print(addr[0]['description'])
            print(addr[0]['tags'])
            print(addr[0]['status']['label'])
            print(addr[0]['last_updated'])
        except IndexError:
            return None
    
    def nbdelete(self, address):
        try:
            self.netbox.ipam.delete_ip_address(address)
        except NotFoundException:
            return None
        return address
    
    def nbcreate(self, address, **kwargs):
        '''nbs.nbcreate('10.2.50.77', tags=["auto"], description="Desktop")
        '''
        self.netbox.ipam.create_ip_address(address, **kwargs)
    
    def nbupdate(self, address, **kwargs):
        self.netbox.ipam.update_ip(address, **kwargs)
    
    def sync(self):
        pass


nbs = NetBoxScanner()

#print(nbs.session)
#nbs.nbquery('10.2.50.99')
#nbs.nbdelete('10.2.50.99')
#nbs.nbcreate('10.2.50.99', tags=["auto"], description="Desktop")
#nbs.nbupdate('10.2.50.99', description="Server")
