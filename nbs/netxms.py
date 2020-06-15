from re import compile
from json import loads

from requests import session, post


re_ipv4 = compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')


class NetXMS(object):
    def __init__(self, address, username, password, tls_verify, unknown):
        self.netxms = Api(address, username, password, tls_verify)
        self.unknown = unknown
        self.hosts = list()

    def run(self):
        objects = self.netxms.all()

        for obj in objects['objects']:
            address = description = ''
            try:
                if obj['ipAddressList']:
                    for ip in obj['ipAddressList']:
                        if re_ipv4.match(ip) and not ip.startswith('127.'):
                            address = ip
                            break
                else:
                    continue
            except KeyError:
                continue
            try:
                description = obj['objectName']
            except KeyError:
                description = self.unknown
            
            if address:
                self.hosts.append((address, description))


class Api(object):
    def __init__(self, base_url, username, password, tls_verify=False):
        self.base_url = base_url
        self.session = session()
        self.session.post(
            f'{self.base_url}/sessions',
            json={'login':username, 'password':password}
        )
    
    def all(self):
        return loads(self.session.get(f'{self.base_url}/objects').text)
