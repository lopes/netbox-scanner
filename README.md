# netbox-scanner
A scanner util for [NetBox](https://netbox.readthedocs.io/en/stable/), because certain networks can be updated automagically.  ;)


## Installation
`netbox-scanner` is available as a Python package via [PyPi](https://pypi.org/project/netbox-scanner/), so you can install it using `pip`:

    $ pip3 install netbox-scanner

You can also download from GitHub:

    $ wget https://github.com/forkd/netbox-scanner/archive/master.zip
    $ unzip netbox-scanner-master.zip -d netbox-scanner
    $ cd netbox-scanner
    $ pip install -r requirements.txt
    $ vi netbox-scanner/config.py  # edit this file, save and exit
    $ python netbox-scanner/netbox-scanner.py

Note that `netbox-scanner` will require [Nmap](https://nmap.org/) and an instance of NetBox ready to use.


## Usage
`netbox-scanner` can be used both in your Python programs or as a script.  To use `netbox-scanner` as a script, simply run `netbox-scanner/netbox-scanner.py` and it'll create its configuration file (`.netbox-scanner.conf`) in your home folder:

    $ python netbox-scanner.py

After that, you'll just need to edit that file with your environment settings and run the script again.

`netbox-scanner` will do the following tasks:

1. It will scan all networks defined in the configuration file.
2. For each discovered host it will:
    1. If host is in NetBox, description is different, and `tag` is equal to that defined in the configuration file, it's description will be updated in NetBox.
    2. If host is not in NetBox, it'll be created.
3. It will iterate through each network to find and delete any hosts registered in NetBox that did not respond to scan, and have the tag defined in the configuration file.

For instance, if some hosts in your monitored networks are eventually down, but you don't want `netbox-scanner` to manage them, just make sure that they **don't** have the tag defined in the configuration file.

Of course, you can use `cron` to automatically run `netbox-scanner`.


## Configuration File
`netbox-scanner` have a configuration file with all parameters needed to scan networks and synchronize them to NetBox.  By default, this file is located at user's home folder and is created when `netbox-scanner.py` is executed for the first time.  Before using `netbox-scanner.py` you should edit that file and fill all variables according to your environment.


## License
`netbox-scanner` is licensed under a MIT license --read `LICENSE` file for more information.
