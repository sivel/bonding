# Pull Requests

Pull requests should be made against the `devel` branch.

# Coding Guidelines

In general, I follow strict pep8 and pyflakes.  All code must pass these tests.

# Permitted Python Modules

Only modules included in the standard library are permitted for use in this application.  This application should not be dependent on any 3rd party modules that would need to be installed external to just Python itself.

# Testing

Basic functional testing is done with `vagrant` and the VirtualBox provider.
Every box should provision without error.
```
cd tests
vagrant up

# Clean-up
vagrant destroy -f
```


The boxes are from official upsteam sources and VMs are named after their OS.
To see a list of OSes run:
```
vagrant status
```


To test a single OS just `vagrant up` its name.
```
vagrant up centos8
```

To rerun just the provisioning step (bonding setup and tests)
```
vagrant up centos8 --provision
```
