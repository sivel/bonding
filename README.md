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
    usage: 
      bonding.py [--nopeers]
      bonding.py --onlypeers
      bonding.py --automated
      bonding.py --unattend --bond=BOND --ip=ADDR --netmask=MASK --iface=IFACE1 --iface=IFACE2 [--iface=IFACE3 ...] [--gateway=GW] [--mode=MODE]
    
    A script used to configure bonding on Linux machines, and to determine which
    interface groups (peers) are available for bonding.
    ------------------------------------------------------------------------------
    https://github.com/sivel/bonding
    
    options:
      -h, --help           show this help message and exit
    
      Peers:
        --onlypeers        Only run the peers portion of this utility, to identify
                           bonded peer interfaces
        --nopeers          Do not run the peers portion of this utility
    
      Unattended:
        --automated        Whether to run this command automated, this is
                           different from unattended which requires information
                           about how to configure the bond. This option requires
                           no additional options and will ignore them
        --unattend         Whether to run this command unattended
        --bond=BOND        The bonded master interface name. Required when using
                           --unattend
        --ip=IP            The IP address to use in the bond. Required when using
                           --unattend
        --netmask=NETMASK  The Netmask to use in the bond. Required when using
                           --unattend
        --iface=IFACE      The interfaces to be used in the bond, specify
                           multiiple times for multiple interfaces. Required when
                           using --unattend
        --gateway=GATEWAY  The default gateway to use for the system, if this is
                           specified, the gateway and gateway dev will be updated.
                           default: none
        --mode=MODE        The bonding mode to be used. default: active-backup

Exit Codes
----------

### Generic

    1: Generic Error

### Automated

    100: There are no interfaces that contain the default route
    101: The gateway device is already a master/bonded interface
    102: There is no IP Address configured on the device containing the default route.
    103: There is no Network Mask configured on the device containing the default route.
    104: Automated bonding will only work when there are exactly 2 peer interfaces, more than 2 found.
    105: Interface is already part of a bond

### Unattended

    200: Not all options provided for an unattended configuration 

### OS Independent	

    300: OS Unsupported
    301: Backup directory already exists

### Red Hat

    400: Red Hat Network Manager enabled

### Debian

    500: Debian ifenslave package is not installed or cannot be located

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