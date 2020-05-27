import logging

from pynetbox import api


class NetBoxScanner(object):
    
    def __init__(self, netbox, hosts, tag, cleanup):
        self.netbox = api(
            netbox['address'],
            netbox['token'],
            ssl_verify=netbox.getboolean('tls_verify')
        )
        self.hosts = hosts
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
        '''Syncs a single host to NetBox.

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
                    logging.info(f'updated: {host[0]}/32 "{aux}" -> "{host[1]}"')
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
                tags=[self.tag],
                description=host[1]
            )
            logging.info(f'created: {host[0]}/32 "{host[1]}"')
            self.stats['created'] += 1

        return True

    def sync(self):
        '''Synchronizes self.hosts to NetBox.
        Returns synching statistics.
        '''
        for s in self.stats:
            self.stats[s] = 0

        logging.info('started: {} hosts'.format(len(self.hosts)))
        for host in self.hosts:
            self.sync_host(host)

        if self.cleanup:
            pass

        logging.info('finished: +{} ~{} -{} !{}'.format(
            self.stats['unchanged'],
            self.stats['created'],
            self.stats['updated'],
            self.stats['deleted'], 
            self.stats['errors']
        ))

        return True
