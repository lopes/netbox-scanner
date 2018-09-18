from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from ipaddress import IPv4Network

from sqlalchemy.orm import sessionmaker
from netbox import NetBox
from netbox.exceptions import NotFoundException

from models import Host, base, engine
from config import TAGS


class NetBoxSync(object):

    def __init__(self, host, tls, token, port, warnings):
        self.netbox = NetBox(host=host, use_ssl=tls, auth_token=token,
            port=port)
        if warnings:
            disable_warnings(InsecureRequestWarning)
        base.metadata.bind = engine
        dbsession = sessionmaker(bind=engine)
        self.session = dbsession()
    
    def get_last_scan_date(self):
        return self.session.query(Host).order_by(Host.date.desc()).first().date
    
    def get_last_scan_all(self):
        return self.session.query(Host).filter(Host.date == self.get_last_scan_date()).all()
    
    def get_last_scan_networks(self):
        return self.session.query(Host.network).filter(Host.date == self.get_last_scan_date()).group_by(Host.network).all()
    
    def in_last_scan(self, address):
        return self.session.query(Host.address).filter(Host.address == address).all()
    
    def sync(self):
        # updating netbox according to last scan
        for host in self.get_last_scan_all():
            nbhost = self.netbox.ipam.get_ip_addresses(address=host.address)
            if nbhost:
                if (TAGS[0] in nbhost[0]['tags']) and (host.name != nbhost[0]['description']):
                    self.netbox.ipam.update_ip('{}/32'.format(host.address), description=host.name)
            else:
                self.netbox.ipam.create_ip_address('{}/32'.format(host.address), tags=TAGS, description=host.name)
        
        # deleting not found ipv4 hosts
        for net in self.get_last_scan_networks():
            for ipv4 in IPv4Network(net[0]):
                address = str(ipv4)
                if not self.in_last_scan(address):
                    nbhost = self.netbox.ipam.get_ip_addresses(address=address)
                    try:
                        if TAGS[0] in nbhost[0]['tags']:
                            self.netbox.ipam.delete_ip_address(address)
                    except IndexError:
                        pass
