#!/usr/bin/env python3

import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='netbox-scanner',
    version='0.5.0',
    author='José Lopes de Oliveira Jr.',
    author_email='jlojunior@gmail.com',
    description='A scanner util for NetBox',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/forkd/netbox-scanner',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
