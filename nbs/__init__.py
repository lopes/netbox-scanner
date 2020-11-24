import logging
import requests

from pynetbox import api


class NetBoxScanner(object):

    def __init__(self, address, token, tls_verify, tag, cleanup):
        if (tls_verify == 'no'):
            session = requests.Session()
            session.verify = False
            self.netbox = api(address, token)
            self.netbox.http_session = session
            self.tag = tag
            self.cleanup = cleanup
            self.stats = {
                'unchanged': 0,
                'created': 0,
                'updated': 0,
                'deleted': 0,
                'errors': 0
            }
        else:
            self.netbox = api(address, token)
            self.tag = tag
            self.cleanup = cleanup
            self.stats = {
                'unchanged': 0,
                'created': 0,
                'updated': 0,
                'deleted': 0,
                'errors': 0
            }

    def sync_host(self, host):
        '''Syncs a single host to NetBox

        host: a tuple like ('10.0.0.1','Gateway')
        returns: True if syncing is good or False for errors
        '''
        try:
            nbhost = self.netbox.ipam.ip_addresses.get(address=host[0])
        except ValueError:
            logging.error(f'duplicated: {host[0]}/32')
            self.stats['errors'] += 1
            return False

        if nbhost:
            if (self.tag in nbhost.tags):
                if (host[1] != nbhost.description):
                    aux = nbhost.description
                    nbhost.description = host[1]
                    nbhost.save()
                    logging.info(
                        f'updated: {host[0]}/32 "{aux}" -> "{host[1]}"')
                    self.stats['updated'] += 1
                else:
                    logging.info(f'unchanged: {host[0]}/32 "{host[1]}"')
                    self.stats['unchanged'] += 1
            else:
                logging.info(f'unchanged: {host[0]}/32 "{host[1]}"')
                self.stats['unchanged'] += 1
        else:
            self.netbox.ipam.ip_addresses.create(
                address=host[0],
                tags=[{"name": self.tag}],
                # dns_name=host[1],
                description=host[1]
            )
            logging.info(f'created: {host[0]}/32 "{host[1]}"')
            self.stats['created'] += 1

        return True

    def garbage_collector(self, hosts):
        '''Removes records from NetBox not found in last sync'''
        nbhosts = self.netbox.ipam.ip_addresses.filter(tag=self.tag)
        for nbhost in nbhosts:
            nbh = str(nbhost).split('/')[0]
            if not any(nbh == addr[0] for addr in hosts):
                nbhost.delete()
                logging.info(f'deleted: {nbhost}')
                self.stats['deleted'] += 1

    def sync(self, hosts):
        '''Syncs hosts to NetBox
        hosts: list of tuples like [(addr,description),...]
        '''
        for s in self.stats:
            self.stats[s] = 0

        logging.info('started: {} hosts'.format(len(hosts)))
        for host in hosts:
            self.sync_host(host)

        if self.cleanup:
            self.garbage_collector(hosts)

        logging.info('finished: .{} +{} ~{} -{} !{}'.format(
            self.stats['unchanged'],
            self.stats['created'],
            self.stats['updated'],
            self.stats['deleted'],
            self.stats['errors']
        ))

        return True
