import socket

import nmap3


class Nmap(object):

    def __init__(self, unknown, networks):
        self.unknown = unknown
        self.networks = networks
        self.hosts = list()
        self.scan_results = {}

    def scan(self):
        nmap = nmap3.NmapHostDiscovery()  # instantiate nmap object
        for item in self.networks:
            temp_scan_result = nmap.nmap_no_portscan(item.replace('\n', ''))
            self.scan_results = {**self.scan_results, **temp_scan_result}
            self.scan_results.pop("stats")
            self.scan_results.pop("runtime")
        return self.scan_results

    def dns_resolution(self):
        # Try to improve DNS resolution since NMAP is not consistent
        for ip, v in self.scan_results.items():
            try:
                name, arpa, ip = socket.gethostbyaddr(ip)
                try:
                    v["hostname"][0]["name"]
                except (TypeError, IndexError):
                    v.update({"hostname": {"name": name, "type": 'PTR'}})
            except socket.herror:
                pass

    def run(self):
        self.scan()
        self.dns_resolution()
        for k,v in self.scan().items():
            try:
                self.hosts.append((
                    k,
                    v['hostname'][0]['name']
                ))
            except (IndexError, KeyError):
                self.hosts.append((
                    k,
                    self.unknown
                ))
