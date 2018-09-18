#!/usr/bin/env python3

from setuptools import setup
from codecs import open

setup(
    name='netbox-scanner',
    packages=['netbox-scanner'],
    version='0.0.2',
    description='',
    long_description=open('README.txt',encoding='utf-8').read(),
    author='José Lopes de Oliveira Jr.',
    license='MIT License',
    url='https://github.com/forkd/netbox-scanner',
    keywords=['netbox','ipam','network','scanner']
)
