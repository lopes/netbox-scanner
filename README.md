# netbox-scanner
A scanner util for NetBox, because certain networks can be updated automagically.  ;)

## Installation
`netbox-scanner` is available as a Python package via PyPi, so you can install it using `pip`:

    $ pip3 install netbox-scanner

Note that `netbox-scanner` will require Nmap and an instance of NetBox ready to use.

## Usage
`netbox-scanner` can be used both in your programs or as a script to be used in shell.

To use `netbox-scanner` as a script, edit `netbox-scanner/config.py` with your setup, and run the command below:

    $ netbox-scanner.py

## License
`netbox-scanner` is licensed under a MIT license --read `LICENSE` file for more information.
