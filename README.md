# netbox-scanner
A scanner util for NetBox, because certain networks can be updated automagically.  ;)

## Installation
`netbox-scanner` is available as a Python package via PyPi, so you can install it using `pip`:

    $ pip3 install netbox-scanner

Another way is to download from GitHub:

    $ wget https://github.com/forkd/netbox-scanner/archive/master.zip
    $ unzip netbox-scanner-master.zip -d netbox-scanner
    $ cd netbox-scanner
    $ pip install -r requirements.txt
    $ vi netbox-scanner/config.py  # edit this file, save and exit
    $ python netbox-scanner/netbox-scanner.py

Note that `netbox-scanner` will require Nmap and an instance of NetBox ready to use.

## Usage
`netbox-scanner` can be used both in your Python programs or as a script.  To use `netbox-scanner` as a script, edit `netbox-scanner/config.py` with your setup, and run the command below:

    $ netbox-scanner.py

`netbox-scanner` will do the following tasks:

1. It will scan all networks defined in `netbox-scanner/config.py` or via parameters.
2. For each discovered host it will:
    1. If host is in NetBox, description is different, and `tag` is set as defined in `netbox-scanner/config.py/TAG`, it'll be updated.
    2. If host is not in NetBox, it'll be created.
3. It will iterate through each network to find and delete any hosts registered in NetBox that did not respond to scan, and have the tag `netbox-scanner/config.py/TAG`.

This way, if some hosts in your monitored networks are eventually down, but you don't want to delete them, just make sure that they doesn't have the tag defined in `netbox-scanner/config.py/TAG`.

To see a list of all available parameters in `netbox-scanner.py`, simple use the `-h` option --please note that all parameters are optional, because all of them can be set using `netbox-scanner/config.py` file:

    $ netbox-scanner.py -h

Of course, you can use `cron` to automatically run `netbox-scanner`.

## License
`netbox-scanner` is licensed under a MIT license --read `LICENSE` file for more information.
