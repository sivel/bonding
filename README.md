Linux Bonding Script
====================

This script is used to configure bonding on Linux machines, and to determine which interface groups (peers) are available for bonding.

Features
--------

* Determination of interface groups (peers)
* Configuration of interface bonding on Linux

Supported Operating Systems
---------------------------

* Red Hat Enterprise Linux (Versions >= 5)
* CentOS (Versions >= 5)
* Fedora (Versions >= 10)
* Debian (Versions >= 5)
* Ubuntu (Versions >= 10.04)

Usage
-----

    $ python bonding.py --help
    Usage: bonding.py [options]
    
    A script used to configure bonding on Linux machines, and to determine which
    interface groups (peers) are available for bonding.
    ------------------------------------------------------------------------------
    https://github.com/sivel/bonding
    
    Options:
      -h, --help           show this help message and exit
    
      Peers:
        --onlypeers        Only run the peers portion of this utility, to identify
                           bonded peer interfaces
        --nopeers          Do not run the peers portion of this utility
    
      Unattended:
        --unattend         Whether to run this command unattended
        --bond=BOND        The bonded master interface name
        --mode=MODE        The bonding mode to be used
        --ip=IP            The IP address to use in the bond
        --netmask=NETMASK  The IP address to use in the bond
        --gateway=GATEWAY  The default gateway to use for the system, if this is
                           specified, the gateway and gateway dev will be updated
        --iface=IFACE      The interfaces to be used in the bond, specify multiple
                           times for multiple interfaces

Bugs
----

Submit bugs, feature requests, etc as [Issues][1]

Contributing
------------

1. Fork it
2. Branch it
3. Commit it
4. Push it
5. Pull request it

[1]: https://github.com/sivel/bonding/issues