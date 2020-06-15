# netbox-scanner
A scanner util for [NetBox](https://netbox.readthedocs.io/en/stable/), because certain networks can be updated *automagically*.  netbox-scanner aims to create, update, and delete hosts (`/32`) in NetBox, either discovered by network scans and synchronized from other sources.

> I know it's no more a scanner since version 2, because the focus now is to synchronize different databases to NetBox, so a better name would be `netbox-sync`.


## Installation
netbox-scanner is compatible with **Python 3.7+**, and can be installed like this:

```bash
$ wget https://github.com/lopes/netbox-scanner/archive/master.zip
$ unzip netbox-scanner-master.zip -d netbox-scanner
$ cd netbox-scanner
$ pip install -r requirements.txt
```

After installation, use the `netbox-scanner.conf` file as an example to create your own and put this file in `/opt/netbox` or prepend its name with a dot and put it in your home directory --`~/.netbox-scanner.conf`.  Keep reading to learn more about configuration.


## Basics
netbox-scanner reads a user-defined source to discover IP addresses and descriptions, and insert them into NetBox.  To control what was previously inserted, netbox-scanner adds tags to each record, so it will know that that item can be handled.  In order to guarantee the integrity of manual inputs, records without such tags will not be updated or removed.

It is important to note that if netbox-scanner cannot define the description for a given host, then it will insert the string defined in the `unknown` parameter.  Users can change those names at their own will.

For NetBox access, this script uses [pynetbox](https://github.com/digitalocean/pynetbox) --worth saying that was tested under NetBox v2.6.7.

### Garbage Collection
If the user marked the `cleanup` option to `yes`, then netbox-scanner will run a garbage collector after the synchronization finishes.  Basically, it will get all IP addresses recorded in NetBox under the same tag.  Then, both lists will be compared: the one just retrieved from NetBox and the list that was synced.  Hosts in the first list that don't appear in the second list will be deleted.


## Configuration
Users can interact with netbox-scanner by command line and configuration file.  The latter is pretty simple and straight forward: the only parameter accepted is the module you want to use.

The configuration file (`netbox-scanner.conf`) is where netbox-scanner looks for details such as authentication data and path to files.  This file can be stored on the user's home directory or on `/opt/netbox`, but if you choose the first option, it must be a hidden file --`.netbox-scanner.conf`.

> Remember that netbox-scanner will always look for this file at home directory, then at `/opt/netbox`, in this order.  The first occurrence will be considered.


## Modules
Since version 2.0, netbox-scanner is based on modules.  This way, this program is just a layer that takes data from one source and inputs in NetBox.  Each module is a file inside the `nbs` directory and is imported by the main script to retrieve data.  This data comes **always** as a 2-dimension array of tuple IP address, description:

```python
[('10.0.1.1', 'Gateway'), ('10.0.1.2', 'Server'), ('10.0.1.64', 'Workstation'), ...]
```


## Nmap Module
Performing the scans is beyond netbox-scanner features, so you must run [Nmap](https://nmap.org/) and save the output as an XML file using the `-oX` parameter.  Since this file can grow really fast, you can scan each network and save it as a single XML file.  You just have to assure that all files are under the same directory before running the script --see `samples/nmap.sh` for an example.

To properly setup this module, you must inform the path to the directory where the XML files reside, define a tag to insert to discovered hosts, and decide if clean up will take place.  Tested on Nmap v7.80.


## Prime Module
This script accesses [Prime](https://www.cisco.com/c/en/us/products/cloud-systems-management/prime-infrastructure/index.html) through RESTful API and all routines are implemented here.  Users only have to point to Prime's API, which looks like `https://prime.domain/webacs/api/v4/`, inform valid credentials allowed to use the API, and fill the other variables, just like in Nmap.

It is important to note everything was tested on Cisco Prime v3.4.0, using API v4.  It was noticed that when trying to retrieve access points data, Prime requires more privileges, so you must explicitly inform that you wish this by using `Prime().run(access_points=True)`.


## NetXMS Module
This module reads the full list of NetXMS' objects and searches for IPv4 addresses discarding loopback addresses.  Unfortunately, NetXMS API is not well documented and it is quite different from other APIs, since it doesn't paginate and uses cookies for authentication.  This way, querying NetXMS can take a couple of minutes depending on the number of records and it can downgrade the system.


## Tests
Some basic tests are implemented under `tests`.  This directory comes with a shell script to run all the tests at once, but before running it, remember to setup some environment variables required by them, such as `NETBOX_ADDRESS` and `NMAP_PATH`.

The script contains a list of all variables, but if you do not want to hardcode passwords, just make sure to export such variables in your shell and properly comment those lines.


## New Modules
New modules should be implemented as a new file with the name of the module, for instance `nbs/netxms.py`.  In this case, a class `NetXMS` should be created in this file with a method `run`.  Finally, in `netbox-scanner.py`, a function `cmd_netxms` should be created to execute the just created class, and another option should be created both in the argument parsing section and in the if structure inside the main block.


## Contributors

- [Jarder Gonzalez](https://github.com/jfjunior) for the great NetXMS' API tips.


## License
netbox-scanner is licensed under an MIT license --read `LICENSE` file for more information.
