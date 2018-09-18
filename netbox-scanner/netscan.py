from datetime import datetime
from random import SystemRandom
from string import ascii_lowercase, digits

from nmap import PortScanner
from cpe import CPE
from sqlalchemy.orm import sessionmaker

from models import Host, base, engine
from config import UNKNOWN_HOSTNAME


class NetworkScanner(object):
    
    def __init__(self):
        base.metadata.bind = engine
        dbsession = sessionmaker(bind=engine)
        self.session = dbsession()
    
    def get_name(self, nbcpe):
        cpe = CPE(nbcpe[0], CPE.VERSION_2_3)
        return '{}:{}:{}'.format(cpe.get_vendor()[0], cpe.get_product()[0], 
            cpe.get_version()[0])

    def scan(self, targets):
        ''''''
        date = datetime.now()
        host_count = 0

        for net in targets:

            nm = PortScanner()
            nm.scan(net, arguments='-T4 -O -F')

            for host in nm.all_hosts():
                addr = nm[host]['addresses']['ipv4']
                name = nm[host]['hostnames'][0]['name']
                try:
                    cpe = nm[host]['osmatch'][0]['osclass'][0]['cpe']
                except (KeyError, IndexError):
                    cpe = None
                if not name:
                    try:
                        name = self.get_name(cpe)
                    except TypeError:
                        name = UNKNOWN_HOSTNAME
                self.session.add(Host(date, net, addr, name, cpe))
                
                host_count += 1
                if host_count >= 300000:  # ~ a /14 network
                    self.session.commit()
                    host_count = 0
            self.session.commit()
