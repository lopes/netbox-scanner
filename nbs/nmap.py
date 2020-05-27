import os
import xml.etree.ElementTree as ET


class Nmap(object):

    def __init__(self, path, unknown):
        self.unknown = unknown
        self.path = path
        self.hosts = list()

    def run(self):
        for f in os.listdir(self.path):
            if not f.endswith('.xml'):
                continue
            abspath = os.path.join(self.path, f)
            tree = ET.parse(abspath)
            root = tree.getroot()

            for host in root.findall('host'):
                try:
                    self.hosts.append((
                        host.find('address').attrib['addr'],
                        host.find('hostnames').find('hostname').attrib['name']
                    ))
                except AttributeError:
                    self.hosts.append((
                        host.find('address').attrib['addr'],
                        self.unknown
                    ))
        