import configparser
import logging
import pynetbox.models.dcim
import requests
import docker
import ipaddress
from collections import deque

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
        except ValueError as e:
            logging.error(e)
            logging.error(f'possibly duplicated: {host[0]}/32')
            self.stats['errors'] += 1
            return False

        if nbhost:
            tag_update = False
            for tag in nbhost.tags:
                if (self.tag == tag.name):
                    tag_update = True
                    break
            if tag_update:
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
                logging.info(f'no-tag(unchanged): {host[0]}/32 "{host[1]}"')
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

    def init_docker(self, dockerDef: configparser.SectionProxy):
        ctype = dockerDef.get('cluster_type')
        clusterType = self.netbox.virtualization.cluster_types.get(name=ctype)
        if clusterType is None:
            self.netbox.virtualization.cluster_types.create(name=ctype,slug=ctype)

    def sync_docker(self, dockerConf: dict[str, str], dockerDef: configparser.SectionProxy):

        try:
            deviceName = dockerConf['device']
            devices = self.netbox.dcim.devices.filter(name=deviceName)
            if len(devices) == 0:
                logging.error(f'No devices matched name {deviceName}')
            device = next(devices)
            site = device.site
            clusterName = f'Docker {device["name"]}'
            cluster = self.netbox.virtualization.clusters.get(name=clusterName)
            if cluster is None:
                logging.info(f'No Cluster exists for device {deviceName}, creating...')
                clusterType = self.netbox.virtualization.cluster_types.get(name=dockerDef.get('cluster_type'))
                clusterParams = {
                    'name': clusterName,
                    'type': clusterType['id'],
                    'status': 'active'
                }
                if site is not None:
                    clusterParams['site'] = site.id
                cluster = self.netbox.virtualization.clusters.create(**clusterParams)
                self.netbox.dcim.devices.update([
                    {
                        'id': device.id, 'cluster': cluster.id
                    }
                ])

            client = docker.DockerClient(base_url=dockerConf['host'])
            networks = client.networks.list()
            containers = client.containers.list()

            networkData = {}

            for container in containers:

                logging.info(f'Processing Container: {container.name}')

                vmName = 'Docker Standalone'
                # is standalone or compose?
                composed = 'com.docker.compose.config-hash' in container.labels
                composeProject = None
                if composed:
                    composeProject = container.labels['com.docker.compose.project']
                    vmName = f'Docker Compose {composeProject}'
                vm = self.netbox.virtualization.virtual_machines.get(name=vmName,cluster_id=cluster.id)

                if vm is None:
                    vm = self.netbox.virtualization.virtual_machines.create(
                        name=vmName,
                        status="active",
                        cluster=cluster.id,
                        device=device.id,
                        site=site.id
                    )
                    logging.info(f'Created missing VM for docker compose project {vmName} with ID {vm.id}')
                    # if composeProject is None:
                    #     # it's a bridge
                    #     if 'bridge' not in networkData:
                    #         net = self.docker_upsert_network(device, nw)
                    #         networkData['bridge'] = net

                containerNetworks = []
                containerNetwork = None
                ips = []
                hasExternalIp = False
                ns = container.attrs.get('NetworkSettings')
                if ns is not None:
                    for networkName in ns['Networks']:
                        if networkName not in networkData:
                            for nw in networks:
                                if nw.name == networkName:
                                    net = self.docker_upsert_network(device, nw)
                                    networkData[networkName] = net
                                    containerNetwork = net
                                    break
                        else:
                            containerNetwork = networkData[networkName]
                        containerNetworks.append({ 'netNetwork': containerNetwork, 'netContainer': ns['Networks'][networkName] })
                        if 'external' in containerNetwork:
                            hasExternalIp = True

                        for nets in containerNetworks:

                            interfaceName = f'compose_{composeProject}' if composed and nets['netNetwork']['name'] != 'bridge' else 'bridge'
                            intParams = {
                                'virtual_machine_id': vm.id,
                                'name': interfaceName
                            }
                            if nets['netNetwork']['vrf'] is not None:
                                intParams['vrf_id'] = nets['netNetwork']['vrf'].id
                            interface = self.netbox.virtualization.interfaces.get(**intParams)
                            if interface is None:
                                del intParams['virtual_machine_id']
                                intParams['virtual_machine'] = vm.id
                                del intParams['vrf_id']
                                if nets['netNetwork']['vrf'] is not None:
                                    intParams['vrf'] = nets['netNetwork']['vrf'].id
                                interface = self.netbox.virtualization.interfaces.create(**intParams)
                                logging.info(f'Created missing Virtual Interface {interfaceName} for VM {vm.id}')

                            containerIp = nets['netContainer']['IPAddress']
                            if containerIp == '' and nets['netNetwork']['name'] == 'host':
                                if nets['netNetwork']['external'] is None:
                                    logging.info(f'Cant process because on host network but no external ip determined!')
                                    continue
                                containerIp = nets['netNetwork']['external'].split('/')[0]
                            ipLookupParams = {
                                'address': f'{containerIp}/32',
                                #'vminterface_id': vm.id
                            }
                            if nets['netNetwork']['vrf'] is not None:
                                ipLookupParams['vrf_id'] = nets['netNetwork']['vrf'].id
                                ipLookupParams['vminterface_id'] = vm.id
                            ip = self.netbox.ipam.ip_addresses.get(**ipLookupParams)
                            if ip is None:
                                ipCreateParams = {
                                    'address': f'{containerIp}/32',
                                }
                                if nets['netNetwork']['vrf'] is not None:
                                    ipCreateParams['assigned_object_type'] = 'virtualization.vminterface'
                                    ipCreateParams['assigned_object_id'] = vm.id
                                    ipCreateParams['vrf'] = nets['netNetwork']['vrf'].id
                                    # address=f'{containerIp}/32',vrf=nets['netNetwork']['vrf'].id,assigned_object_type='virtualization.vminterface',assigned_object_id=interface.id
                                ip = self.netbox.ipam.ip_addresses.create(**ipCreateParams)
                                logging.info(f'Created missing IP {containerIp} on {interfaceName} interface')
                            ips.append(ip)

                tcp = False
                ports = []
                ipIds = []

                for containerPortDesc in container.ports:
                    if 'tcp' in containerPortDesc:
                        tcp = True
                    portList = container.ports[containerPortDesc]
                    if portList is not None:
                        ports.append(portList[0]['HostPort'])

                for ip in ips:
                    ipIds.append(ip.id)

                serviceName = container.name
                service = self.netbox.ipam.services.get(name=serviceName,virtual_machine_id=vm.id)
                if service is None:
                    serviceDescription = None
                    if 'org.opencontainers.image.title' in container.labels:
                        serviceDescription = container.labels['org.opencontainers.image.title']
                    if 'org.opencontainers.image.description' in container.labels:
                        if serviceDescription is not None:
                            serviceDescription = f'{serviceDescription} - {container.labels["org.opencontainers.image.description"]}'
                        else:
                            serviceDescription = container.labels['org.opencontainers.image.description']

                    serviceParams = {
                        'name': serviceName,
                        'virtual_machine': vm.id,
                        'ipaddresses': ipIds
                    }
                    if serviceDescription is not None:
                        # https://stackoverflow.com/a/2872519/1469797
                        serviceParams['description'] = (serviceDescription[:50] + '..') if len(serviceDescription) > 50 else serviceDescription
                    if len(ports) > 0:
                        serviceParams['ports'] = ports
                        serviceParams['protocol'] = 'tcp' if tcp else 'udp'
                    else:
                        serviceParams['ports'] = [1]
                        serviceParams['protocol'] = 'tcp'

                    # if serviceDescription is not None:
                    #     service = self.netbox.ipam.services.create(name=serviceName,virtual_machine=vm.id,description=serviceDescription,ipaddresses=ipIds,ports=ports,protocol='tcp' if tcp else 'udp')
                    # else:
                    #     service = self.netbox.ipam.services.create(name=serviceName,virtual_machine=vm.id,ipaddresses=ipIds,ports=ports,protocol='tcp' if tcp else 'udp')
                    service = self.netbox.ipam.services.create(**serviceParams)
                    logging.info(f'Created missing service {service} on VM {vm.id}')
                else:

                    serviceUpdateParams = {
                        'ipaddresses': ipIds,
                        'id': service.id
                    }
                    if len(ports) > 0:
                        serviceUpdateParams['ports'] = ports
                        serviceUpdateParams['protocol'] = 'tcp' if tcp else 'udp'

                    # update addresses and ports
                    self.netbox.ipam.services.update([
                        serviceUpdateParams
                    ])
                    logging.info(f'Update addresses and ports for service {service} on VM {vm.id}')

        except ValueError as e:
            logging.error(e)
            return False

    # def docker_upsert_vm(self, cluster, device: pynetbox.models.dcim.Devices):

    def docker_upsert_network(self,device: pynetbox.models.dcim.Devices, d_network: docker.client.NetworkCollection.model):
        primaryIp = None
        if device.primary_ip4 is not None:
            primaryIp = device.primary_ip4.address

        networkName = d_network.name
        driver = d_network.attrs.get('Driver')
        if networkName == 'host' or networkName == 'none' or driver == 'host':
            return {
                'name': networkName,
                'vrf': None,
                'range': None,
                'internal': primaryIp,
                'external': primaryIp
            }
        # deal with this later
        if driver != 'bridge':
            return {
                'name': networkName,
                'vrf': None,
                'range': None,
                'internal': None,
                'external': None
            }

        vrf = self.netbox.ipam.vrfs.get(name=f'Docker on {device["name"]}')
        if vrf is None:
            vrf = self.netbox.ipam.vrfs.create(name=f'Docker on {device["name"]}', rd=f'docker-{device["name"]}')
            logging.info(f'Created missing VRF for docker on {device["name"]} with ID {vrf.id}')

        range = self.netbox.ipam.ip_ranges.get(description=networkName,vrf_id=vrf.id)
        if range is None:
            subnet = d_network.attrs.get('IPAM')['Config'][0]['Subnet']
            subnet_range = self.get_subnet_range(subnet)
            range = self.netbox.ipam.ip_ranges.create(
                description=networkName,
                vrf=vrf.id,
                start_address=f'{subnet_range[0].exploded}/32',
                end_address=f'{subnet_range[1].exploded}/32'
            )
            logging.info(f'Created missing IP Range for docker network {networkName} {range.start_address} => {range.end_address} in VRF {vrf.id}')

        return {
            'name': networkName,
            'vrf': vrf,
            'range': range,
            'internal': None,
            'external': primaryIp
        }
        # subnet = d_network.attrs.get('IPAM')['Config'][0]['Subnet']

    def get_subnet_range(self, subnet):
        ip_range = ipaddress.ip_network(subnet)
        hosts = ip_range.hosts()
        firstHost = next(ip_range.hosts())

        # https://stackoverflow.com/a/48232574/1469797
        dd = deque(hosts, maxlen=1)
        lastHost = dd.pop()
        return [firstHost, lastHost]