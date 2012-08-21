#!/usr/bin/env python
import fcntl, socket, struct, IN, string, array, os, sys, re, platform, time, shutil, syslog
from optparse import OptionParser, OptionGroup
from distutils.version import LooseVersion

TIMEOUT = 0.05       # In seconds
USEREALSRCMAC = True # Use the real source MAC address or 00:00:00:00:00:00

GREEN  = '\033[92m'
RESET  = '\033[0m'
RED    = '\033[91m'
YELLOW = '\033[93m'
WHITE  = '\033[97m'
CYAN   = '\033[96m'
PINK   = '\033[95m'
BLUE   = '\033[94m'

# Non DIX types (if_ether.h)
ETH_P_ALL = 0x0003             # Every packet (be careful!!!)

# Socket configuration controls (sockios.h)
SIOCGIFNAME     = 0x8910       # get iface name
SIOCGIFCONF     = 0x8912       # get iface list
SIOCGIFFLAGS    = 0x8913       # get flags
SIOCSIFFLAGS    = 0x8914       # set flags
SIOCGIFADDR     = 0x8915       # get PA address
SIOCGIFDSTADDR  = 0x8917       # get remote PA address
SIOCGIFBRDADDR  = 0x8919       # get broadcast PA address
SIOCGIFNETMASK  = 0x891b       # get network PA mask
SIOCGIFMETRIC   = 0x891d       # get metric
SIOCGIFMEM      = 0x891f       # get memory address (BSD)
SIOCGIFMTU      = 0x8921       # get MTU size
SIOCGIFENCAP    = 0x8925       # get/set encapsulations
SIOCGIFHWADDR   = 0x8927       # Get hardware address
SIOCGIFSLAVE    = 0x8929       # Driver slaving support
SIOCGIFINDEX    = 0x8933       # name -> if_index mapping
SIOGIFINDEX     = SIOCGIFINDEX # misprint compatibility :-)
SIOCGIFPFLAGS   = 0x8935
SIOCGIFCOUNT    = 0x8938       # get number of devices
SIOCGIFBR       = 0x8940       # Bridging support
SIOCGIFTXQLEN   = 0x8942       # Get the tx queue length
SIOCGIFDIVERT   = 0x8944       # Frame diversion support
SIOCETHTOOL     = 0x8946       # Ethtool interface
SIOCGIFMAP      = 0x8970       # Get device parameters
SIOCGIFVLAN     = 0x8982       # 802.1Q VLAN support

# Ethtool CMDs currently supported (ethtool.h)
ETHTOOL_GLINK   = 0x0000000a   # Get link status

# Standard interface flags (net/if.h)
IFF_UP          = 0x1          # Interface is up.
IFF_BROADCAST   = 0x2          # Broadcast address valid.
IFF_DEBUG       = 0x4          # Turn on debugging.
IFF_LOOPBACK    = 0x8          # Is a loopback net.
IFF_POINTOPOINT = 0x10         # Interface is point-to-point link.
IFF_NOTRAILERS  = 0x20         # Avoid use of trailers.
IFF_RUNNING     = 0x40         # Resources allocated.
IFF_NOARP       = 0x80         # No address resolution protocol.
IFF_PROMISC     = 0x100        # Receive all packets.
IFF_ALLMULTI    = 0x200        # Receive all multicast packets.
IFF_MASTER      = 0x400        # Master of a load balancer.
IFF_SLAVE       = 0x800        # Slave of a load balancer.
IFF_MULTICAST   = 0x1000       # Supports multicast.
IFF_PORTSEL     = 0x2000       # Can set media type.
IFF_AUTOMEDIA   = 0x4000       # Auto media select active.

def get_default_gateway():
  for line in open('/proc/net/route').readlines():
    fields = line.strip().split()
    if fields[1] != '00000000' or not int(fields[3], 16) & 2:
      continue
    return socket.inet_ntoa(struct.pack('<L', int(fields[2], 16)))

def get_default_gateway_dev():
  for line in open('/proc/net/route').readlines():
    fields = line.strip().split()
    if fields[1] != '00000000' or not int(fields[3], 16) & 2:
      continue
    return fields[0]

def get_network_addr(ifname, type):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    return socket.inet_ntoa(fcntl.ioctl(
      s.fileno(),
      type,
      struct.pack('256s', ifname[:15])
    )[20:24])
  except IOError:
    return None

def get_mac_addr_raw(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return fcntl.ioctl(
    s.fileno(),
    SIOCGIFHWADDR,
    struct.pack('256s', ifname[:15])
  )[18:24]

def get_mac_addr(ifname):
  return ''.join(['%02x:' % ord(char) for char in get_mac_addr_raw(ifname)])[:-1]

def is_iface_flags(ifname, type):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  flags, = struct.unpack('H', fcntl.ioctl(
    s.fileno(),
    SIOCGIFFLAGS,
    struct.pack('256s', ifname[:15])
  )[16:18])
  return (flags & type ) != 0

def set_iface_flag(ifname, flag, flags = None):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  if not flags:
    flags = 0
    ifreq = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, struct.pack('256s', ifname[:15]))
    (flags,) = struct.unpack('16xH', ifreq[:18])
  flags |= flag
  ifreq = struct.pack('4s12xH', ifname, flags)
  fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifreq)
  s.close()
  return flags

def get_iface_list():
  ifaces = []
  for line in open('/proc/net/dev').readlines():
    fields = line.strip().split()
    if ':' in fields[0]:
      iface = fields[0].split(':')
      ifaces.append(iface[0])
  return sorted(ifaces)

def get_iface_link_status(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  ecmd = array.array('B', struct.pack('2I', ETHTOOL_GLINK, 0))
  ifreq = struct.pack('16sP', ifname, ecmd.buffer_info()[0])
  fcntl.ioctl(s, SIOCETHTOOL, ifreq)
  res = ecmd.tostring()
  return bool(struct.unpack('4xI', res)[0])

def get_slave_iface_list(ifname):
  try:
    if is_iface_master(ifname):
      bond = open('/sys/class/net/%s/bonding/slaves' % ifname).read()
      return bond.split()
  except IOErrror:
    return False

def is_iface_slave(ifname):
  return is_iface_flags(ifname, IFF_SLAVE)

def is_iface_master(ifname):
  return is_iface_flags(ifname, IFF_MASTER)

def is_iface_up(ifname):
  return is_iface_flags(ifname, IFF_UP)

def is_iface_loopback(ifname):
  return is_iface_flags(ifname, IFF_LOOPBACK)

def get_network_mask(ifname):
  return get_network_addr(ifname, SIOCGIFNETMASK)

def get_ip_address(ifname):
  return get_network_addr(ifname, SIOCGIFADDR)

def confirm(prompt = None, default = False):
  if prompt is None:
    prompt = 'Confirm'

  if default:
    prompt = '%s %s[%s]%s|%s: ' % (prompt, PINK, 'Y', RESET, 'n')
  else:
    prompt = '%s %s[%s]%s|%s: ' % (prompt, PINK, 'N', RESET, 'y')

  try:
    while True:
      ans = raw_input(prompt)
      if not ans:
        return default
      if ans not in ['y', 'Y', 'n', 'N']:
        print 'please enter y or n.'
        continue
      if ans == 'y' or ans == 'Y':
        return True
      if ans == 'n' or ans == 'N':
        return False
  except KeyboardInterrupt:
    print '\nExiting'
    sys.exit(0)

def defaults(prompt, default):
  prompt = '%s %s[%s]%s: ' % (prompt, PINK, default, RESET)
  try:
    response = raw_input(prompt).strip()
    if response:
      return response
    else:
      return default
  except KeyboardInterrupt:
    print '\nExiting'
    sys.exit(0)

def peers(quiet = True):
  if os.geteuid() != 0:
    print '%sroot privileges are needed to properly check for bonding peers. Skipping...%s' % (RED, RESET)
    return {}

  syslog.openlog('bonding')
  syslog.syslog('Scanning for bonding interface peers')

  ifaces = get_iface_list()

  # Enable all normal interfaces
  for iface in ifaces:
    if is_iface_loopback(iface) or is_iface_master(iface):
      continue
    set_iface_flag(iface, IFF_UP)

  secondaries = []
  groups = {}
  for send_iface in ifaces:
    if not quiet:
      print '.',
      sys.stdout.flush()
    if is_iface_loopback(send_iface) or is_iface_master(send_iface) or send_iface in secondaries:
      continue

    # The data required for building the frame
    static = 'IF%sIF' % send_iface # Static data for frame payload that includes the sending interface name
    payload = '%s%s' % (static, os.urandom(46 - len(static))) # Build the rest of the payload using random data
    dstMac = '\xff\xff\xff\xff\xff\xff' # Broadcast FF:FF:FF:FF:FF:FF
    if USEREALSRCMAC:
      srcMac = get_mac_addr_raw(send_iface) # The real MAC address of the sending interface
    else:
      srcMac = '\x00\x00\x00\x00\x00\x00' # Invalid source MAC
    frameType = '\x50\x44' # Unregistered EtherType, used in this case for Interface Peer Discovery

    # Set up the sending interface socket
    s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s1.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, send_iface + '\0')
    s1.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s1.bind((send_iface, 0))
    s1.setblocking(0)

    for recv_iface in ifaces:
      if not quiet:
        print '.',
        sys.stdout.flush()
      if is_iface_loopback(recv_iface) or is_iface_master(recv_iface) or recv_iface == send_iface:
        continue

      # Set up the receiving interface socket
      s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
      s2.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, recv_iface + '\0')
      s2.bind((recv_iface, 0))
      s2.settimeout(TIMEOUT)

      # Place current reciving interface into permiscuous mode
      current_flags = 0
      ifreq = fcntl.ioctl(s2.fileno(), SIOCGIFFLAGS, struct.pack('256s', recv_iface[:15]))
      (current_flags,) = struct.unpack('16xH', ifreq[:18])
      current_flags |= IFF_PROMISC
      ifreq = struct.pack('4s12xH', recv_iface, current_flags)
      fcntl.ioctl(s2.fileno(), SIOCSIFFLAGS, ifreq)

      # Try sending and receiving 3 times to give us better chances of catching the send
      # Generally we always catch on the first time
      for i in xrange(0, 3):
        s1.sendall('%s%s%s%s' % (dstMac, srcMac, frameType, payload))
        try:
          data = s2.recv(60)
        except socket.timeout:
          continue
        recvFrameType = data[12:14]
        recvPayload = data[14:]
        if payload == recvPayload and recvFrameType == frameType:
          if send_iface not in groups:
            groups[send_iface] = []
          groups[send_iface].append(recv_iface)
          secondaries.append(recv_iface)
          break

      # Take the receiving interface out of permiscuous mode
      current_flags ^= IFF_PROMISC
      ifreq = struct.pack('4s12xH', recv_iface, current_flags)
      fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifreq)

      s2.close()

    s1.close()

  for iface in sorted(groups.keys()):
    syslog.syslog('Interface group: %s %s' % ( iface, ' '.join(groups[iface]) ) )

  syslog.syslog('Scan for bonding interface peers completed')

  if not quiet:
    print 'Done'
  return groups

def collectBondInfo(groups, distro):
  ifaces = get_iface_list()
  bonds = {}
  allSlaves = {}
  for iface in ifaces:
    if is_iface_master(iface) and get_slave_iface_list(iface):
      slaves = get_slave_iface_list(iface)
      if slaves:
        bonds[iface] = slaves
        for slave in slaves:
          allSlaves[slave] = iface
      else:
        bonds[iface] = []

  bondRange = range(0,101)
  if bonds:
    print '%s\nThe following bonded interfaces are already configured:\n' % YELLOW
    for bondIface in bonds:
      print '%s' % bondIface
      bondInt = int(bondIface.replace('bond', ''))
      del bondRange[bondRange.index(bondInt)]
      for slave in bonds[bondIface]:
        print '\t%s' % slave
  else:
    print '''\n%sThere are no bonded interfaces currently present in the running
configuration on this server. This does not take into account configurations
that have not yet been loaded into the running configuration.''' % GREEN

  print '%s' % RESET

  children = None
  if groups:
    selections = {}
    print 'Interface groups available for configuration:\n'
    i=1
    for key in reversed(groups.keys()):
      group = [key] + groups[key]
      print '%s%s) %s%s' % (PINK, i, ' '.join(sorted(group)), RESET)
      selections[str(i)] = group
      i += 1

    try:
      response = raw_input('\nWhich numerical interface group from above would you like to configure? (leave blank or hit enter to perform manual entry later) ').strip()
      if not response:
        children = None
      elif response not in selections:
        print '%sInvalid selection. Can not continue.%s' % (RED, RESET)
        sys.exit(1)
      else:
        children = selections[response]
    except KeyboardInterrupt:
      sys.exit(0)

  bond = defaults('What is the name of the bond interface you are confguring?', 'bond%s' % bondRange[0])
  if bond in ifaces and is_iface_master(bond) and get_slave_iface_list(bond):
    del bondRange[bondRange.index(int(bond.replace('bond', '')))]
    bond = defaults('%s%s is already configured as a master interface.%s\nWhat is the name of the bond interface you are confguring?' % (RED, bond, RESET), 'bond%s' % bondRange[0])
    if bond in ifaces and is_iface_master(bond) and get_slave_iface_list(bond):
      print '%sA valid bond interface was not provided. Can not continue%s' % (RED, RESET)
      sys.exit(1)

  print '%sThe bonded interface will be named: %s%s%s\n' % (GREEN, YELLOW, bond, RESET)

  modeMap = {
    '0': 'balance-rr',
    '1': 'active-backup',
    '2': 'balance-xor',
    '3': 'broadcast',
    '4': '802.3ad',
    '5': 'balance-tlb',
    '6': 'balance-alb',
  }

  modes = [
    '0', 'balance-rr',
    '1', 'active-backup',
    '2', 'balance-xor',
    '3', 'broadcast',
    '4', '802.3ad',
    '5', 'balance-tlb',
    '6', 'balance-alb',
  ]

  mode = defaults('Which bonding mode do you want to use for %s?' % bond, 'active-backup')
  if mode not in modes:
    mode = defaults('%sThe bonding mode may be one of %s.%s\nWhat bonding mode do you want to use for %s?' % (RED, ', '.join(modes), RESET, bond), 'active-backup')
    if mode not in modes:
      print '%sA valid bonding mode was not provided. Can not continue%s' % (RED, RESET)
      sys.exit(1)

  extraOpts = ''
  if mode == '4' or mode == '802.3ad':
    if distro == 'redhat':
      extraOpts = ' lacp_rate=1'
    elif distro == 'debian':
      extraOpts = '    bond-lacp-rate 1'

  if mode in modeMap:
    mode = modeMap[mode]

  print '%sThe bonded interface will use mode %s%s%s\n' % (GREEN, YELLOW, mode, RESET)

  if not children:
    children = defaults('What are the interfaces that will be part of the bond?', 'eth0 eth1')
    if children:
      children = children.split()
    else:
      print '%sYou did not provide any interfaces to be part of %s%s' % (RED, bond, RESET)
      sys.exit(1)

  bail = False
  ipAddresses = {}
  for child in children:
    if child not in ifaces:
      print '%sYou provided an interface name that does not exist on this system: %s%s' % (RED, child, RESET)
      bail = True
    elif is_iface_slave(child):
      print '%sYou provided an interface name that is already part of an already configured bond (%s): %s%s' % ( RED, allSlaves[child], child, RESET )
      bail = True

    ipAddress = get_ip_address(child)
    if ipAddress:
      ipAddresses[ipAddress] = child

  if bail:
    sys.exit(1)

  print '%sThe interfaces that will be used for %s%s%s will be: %s%s%s\n' % (GREEN, YELLOW, bond, GREEN, YELLOW, ' '.join(children), RESET)

  if len(ipAddresses) > 1:
    print '%sThe following IP addresses were found:' % YELLOW
    for addr in ipAddresses:
      print '%s: %s' % (ipAddresses[addr], addr)
    ipAddress = defaults('\n%sWhich of the above IP addresses do you want to use for the primary IP for %s?' % (RESET, bond), ipAddresses.keys()[0])
  else:
    ipAddress = ipAddresses.keys()
    if ipAddress:
      ipAddress = ipAddress[0]
    else:
      ipAddress = ''
    ipAddress = defaults('What IP address do you want to use for the primary IP for %s?' % bond, ipAddress)

  try:
    socket.inet_aton(ipAddress)
  except socket.error:
    print '%s"%s" is not a valid IP address.%s' % (RED, ipAddress, RESET)
    sys.exit(1)

  print '%sThe IP address that will be used for %s%s%s will be: %s%s%s\n' % (GREEN, YELLOW, bond, GREEN, YELLOW, ipAddress, RESET)

  netmask = None
  if ipAddress in ipAddresses:
    netmask = get_network_mask(ipAddresses[ipAddress])
  if not netmask:
    netmask = defaults('No Network Mask was located. What Network Mask do you want to use for %s?' % bond, '255.255.255.0')
  else:
    netmask = defaults('What Network Mask do you want to use for %s?' % bond, netmask)

  print '%sThe Network Mask that will be used for %s%s%s will be: %s%s%s\n' % (GREEN, YELLOW, bond, GREEN, YELLOW, netmask, RESET)

  gatewayDev = get_default_gateway_dev()
  print '%sCurrent default gateway details from the running configuration:' % YELLOW
  print 'Gateway IP:  %s' % get_default_gateway()
  print 'Gateway Dev: %s' % gatewayDev
  print 'This does not take into account configurations that have not yet been loaded into the running configuration.'
  print '%s' % RESET

  changeGWDefaultResponse = True
  if gatewayDev.startswith('bond'):
    changeGWDefaultResponse = False
  changeGW = confirm('Change the default gateway and gateway device on this system?', changeGWDefaultResponse)
  if changeGW:
    gateway = get_default_gateway()
    if not gateway:
      gateway = defaults('No default gateway was located on this system.\nWhat default gateway do you want to use for this system? It must be accessible from %s.' % bond, '.'.join(ipAddress.split('.')[0:3]) + '.1')
    else:
      gateway = defaults('%s accessible default gateway for this system?' % bond, gateway)
    print '%sThe default gateway that will be used for %s%s%s will be: %s%s%s\n' % (GREEN, YELLOW, bond, GREEN, YELLOW, gateway, RESET)
  else:
    gateway = False
    print '%sThe default gateway will %sNOT%s be changed for %s%s%s\n' % (GREEN, YELLOW, GREEN, YELLOW, bond, RESET)

  return {'master': bond, 'slaves': children, 'ipaddr': ipAddress, 'netmask': netmask, 'gateway': gateway, 'mode': mode, 'opts': extraOpts}

def doBond(groups = {}, bondInfo = {}):
  dist = platform.dist()
  distro = dist[0].lower()
  version = dist[1]
  didBonding = False
  if ( distro in ['redhat', 'centos'] and LooseVersion(version) >= '5' ) or ( distro in ['fedora'] and LooseVersion(version) >= '10' ):
    bondRHEL(version, distro, groups, bondInfo)
    didBonding = True
  elif ( distro in ['ubuntu'] and LooseVersion(version) >= '10' ) or ( distro in ['debian'] and LooseVersion(version) >= '5' ):
    bondDeb(groups, bondInfo)
    didBonding = True

  if not didBonding:
    print '\n%sThis bonding script does not support the OS that you are attempting to configure bonding on.%s' % (RED, RESET)
    sys.exit(1)

  print '\n%sBonding has been configured! The only thing left is to restart networking.%s' % (GREEN, RESET)

def bondRHEL(version, distro, groups, bondInfo):
  syslog.openlog('bonding')
  syslog.syslog('Bonding configuration started')

  if not bondInfo:
    bondInfo = collectBondInfo(groups, 'redhat')
    syslog.syslog('Interactively collecting bonding configuration')
  else:
    syslog.syslog('Bonding configuration supplied for an unattended run')

  hasNM = False
  if ( LooseVersion(version) >= '6' and distro in ['redhat', 'centos'] ) or distro == 'fedora':
    hasNM = True
    syslog.syslog('This OS was identified as including NetworkManager')

    if os.path.exists('/var/run/NetworkManager/NetworkManager.pid'):
      pid = open('/var/run/NetworkManager/NetworkManager.pid').read().strip()
      if os.path.exists('/proc/%s/comm' % pid) and open('/proc/%s/comm' % pid).read().strip() == 'NetworkManager':
        print '%sNetworkManager must be stopped and the network service started before you can run this script.%s' % (RED, RESET)
        syslog.syslog('NetworkManager is running, cannot continue')
        sys.exit(1)

  date = time.strftime('%Y-%m-%d')
  netScripts = '/etc/sysconfig/network-scripts'
  backupDir = '%s/%s-bak-%s' % (netScripts, bondInfo['master'], date)

  syslog.syslog('Backing up configuration files before modification to %s' % backupDir)
  print 'Backing up existing ifcfg files to %s' % backupDir
  if not os.path.isdir(backupDir):
    os.mkdir(backupDir, 0755)
  else:
    print '%sThe backup directory already exists, to prevent overwriting required backup files, this script will exit.%s' % (RED, RESET)
    syslog.syslog('The backup directory already exists, cannot coninute')
    sys.exit(1)
  for iface in bondInfo['slaves'] + [bondInfo['master']]:
    if os.path.exists('%s/ifcfg-%s' % (netScripts, iface)):
      shutil.move('%s/ifcfg-%s' % (netScripts, iface), backupDir)

  print 'Configuring bonding...'
  syslog.syslog('Writing %s/ifcfg-%s' % (netScripts, bondInfo['master']))
  bfh = open('%s/ifcfg-%s' % (netScripts, bondInfo['master']), 'w')
  ifaceCfg = '''DEVICE=%(master)s
BOOTPROTO=none
ONBOOT=yes
NETMASK=%(netmask)s
IPADDR=%(ipaddr)s
USERCTL=no
BONDING_OPTS="mode=%(mode)s miimon=100%(opts)s"''' % bondInfo
  if hasNM:
    ifaceCfg += '\nNM_CONTROLLED=no'
  bfh.write('%s\n' % ifaceCfg)
  bfh.close()

  for iface in bondInfo['slaves']:
    syslog.syslog('Writing %s/ifcfg-%s' % (netScripts, iface))
    sfh = open('%s/ifcfg-%s' % (netScripts, iface), 'w')
    ifaceCfg = '''DEVICE=%(slave)s
BOOTPROTO=none
ONBOOT=yes
MASTER=%(master)s
SLAVE=yes
USERCTL=no
HWADDR=%(hwaddr)s''' % dict(bondInfo, slave = iface, hwaddr = get_mac_addr(iface).upper())
    if hasNM:
      ifaceCfg += '\nNM_CONTROLLED=no'
    sfh.write('%s\n' % ifaceCfg)
    sfh.close()

  syslog.syslog('Writing /etc/modprobe.d/bonding.conf')
  mfh = open('/etc/modprobe.d/bonding.conf', 'a+')
  mfh.write('alias %s bonding\n' % bondInfo['master'])
  mfh.close()

  if bondInfo['gateway']:
    shutil.copy('/etc/sysconfig/network', backupDir)
    syslog.syslog('Writing /etc/sysconfig/network')
    nfh = open('/etc/sysconfig/network')
    netCfg = nfh.readlines()
    nfh.close()

    newNetCfg = ''
    addedGWDev = False
    addedGW = False
    addedNZC = False
    for line in netCfg:
      if line.startswith('GATEWAYDEV='):
        newNetCfg += 'GATEWAYDEV=%s\n' % bondInfo['master']
        addedGWDev = True
      elif line.startswith('GATEWAY='):
        newNetCfg += 'GATEWAY=%s\n' % bondInfo['gateway']
        addedGW = True
      elif line.startswith('NOZEROCONF='):
        newNetCfg += 'NOZEROCONF=yes\n'
        addedNZC = True
      else:
        newNetCfg += line

    if not addedGW:
      newNetCfg += 'GATEWAYDEV=%s\n' % bondInfo['master']

    if not addedGWDev:
      newNetCfg += 'GATEWAY=%s\n' % bondInfo['gateway']

    if not addedNZC:
      newNetCfg += 'NOZEROCONF=yes\n'

    nfh = open('/etc/sysconfig/network', 'w+')
    nfh.write(newNetCfg)
    nfh.close()

  syslog.syslog('Bonding configuration has completed')

def bondDeb(groups, bondInfo):
  syslog.openlog('bonding')
  syslog.syslog('Bonding configuration started')

  if not os.path.exists('/sbin/ifenslave'):
    print '%sThe ifenslave package must be installed for bonding to work%s' % (RED, RESET)
    syslog.syslog('/sbin/ifenslave is missing, cannot continue')
    sys.exit(1)

  if not bondInfo:
    bondInfo = collectBondInfo(groups, 'debian')
    syslog.syslog('Interactively collecting bonding configuration')
  else:
    syslog.syslog('Bonding configuration supplied for an unattended run')

  date = time.strftime('%Y-%m-%d')
  netDir = '/etc/network'
  backupDir = '%s/%s-bak-%s' % (netDir, bondInfo['master'], date)

  syslog.syslog('Backing up configuration files before modification to %s' % backupDir)
  print 'Backing up existing ifcfg files to %s' % backupDir
  if not os.path.isdir(backupDir):
    os.mkdir(backupDir, 0755)
  else:
    print '%sThe backup directory already exists, to prevent overwriting required backup files, this script will exit.%s' % (RED, RESET)
    syslog.syslog('The backup directory already exists, cannot coninute')
    sys.exit(1)

  shutil.copyfile('/etc/network/interfaces', '%s/interfaces' % backupDir)

  ifh = open('/etc/network/interfaces')
  interfacesLines = ifh.readlines()
  ifh.close()

  interfacesDict = {'auto': []}
  iface = None
  for line in interfacesLines:
    if line.startswith('iface'):
      fields = line.split()
      iface = fields[1]
      interfacesDict[iface] = {'stanza': fields[2:], 'conf': {'dns-nameservers': '', 'dns-search': ''}}
    elif line.startswith('auto'):
      fields = line.split()
      interfacesDict['auto'].append(fields[1])
    elif re.match('^\s', line) and iface:
      line = line.strip()
      if line.startswith('#') or not line:
        continue
      fields = line.split()
      interfacesDict[iface]['conf'][fields[0]] = ' '.join(fields[1:])

  nameservers = None
  search = None
  for iface in bondInfo['slaves']:
    if iface in interfacesDict and interfacesDict[iface]['conf']['dns-nameservers'] and not nameservers:
      nameservers = interfacesDict[iface]['conf']['dns-nameservers']
    if iface in interfacesDict and interfacesDict[iface]['conf']['dns-search'] and not search:
      search = interfacesDict[iface]['conf']['dns-search']

  slaves = bondInfo['slaves']
  bondInfo['slaves'] = ' '.join(bondInfo['slaves'])

  syslog.syslog('Writing /etc/network/interfaces')

  interfacesCfg = ''
  for slave in slaves:
    interfacesCfg += """auto %s
iface %s inet manual
    bond-master %s
\n""" % (slave, slave, bondInfo['master'])

  interfacesCfg += """auto %(master)s
iface %(master)s inet static
    address %(ipaddr)s
    netmask %(netmask)s
    bond-mode %(mode)s
    bond-miimon 100
    slaves %(slaves)s
""" % bondInfo

  if bondInfo['opts']:
    interfacesCfg += """%s
""" % bondInfo['opts']

  if nameservers:
    interfacesCfg += """    dns-nameservers %s
""" % nameservers

  if search:
    interfacesCfg += """    dns-search %s
""" % search

  if bondInfo['gateway']:
    interfacesCfg += """    gateway %s
""" % bondInfo['gateway']

  for key in reversed(interfacesDict.keys()):
    if key not in ['auto'] and key not in slaves:
      if key in interfacesDict['auto']:
        interfacesCfg += """
auto %s""" % key
      interfacesCfg += """
iface %s %s
""" % (key, ' '.join(interfacesDict[key]['stanza']))
      for conf in interfacesDict[key]['conf']:
        if interfacesDict[key]['conf'][conf]:
          interfacesCfg += """    %s %s
""" % (conf, interfacesDict[key]['conf'][conf])

  ifh = open('/etc/network/interfaces', 'w+')
  ifh.write('%s\n' % interfacesCfg)
  ifh.close()

  syslog.syslog('Writing /etc/modprobe.d/bonding.conf')
  mfh = open('/etc/modprobe.d/bonding.conf', 'a+')
  mfh.write('alias %s bonding\n' % bondInfo['master'])
  mfh.close()

  syslog.syslog('Bonding configuration has completed')

  print '\n%sNOTE: After you restart networking you will also have to manually remove the IP address used in the bond from the interface that previously held it as debian/ubuntu will not do this.%s' % (YELLOW, RESET)

  print "\n%sAdditionally, be aware that networking will likely mark all slave interfaces as down if you use /etc/init.d/networking restart, you will have to ifdown and then ifup each individually, this will require DRAC access if the first bond has the default gateway.%s" % (YELLOW, RESET)

def handleArgs():
  modeMap = {
    '0': 'balance-rr',
    '1': 'active-backup',
    '2': 'balance-xor',
    '3': 'broadcast',
    '4': '802.3ad',
    '5': 'balance-tlb',
    '6': 'balance-alb',
  }

  modes = [
    '0', 'balance-rr',
    '1', 'active-backup',
    '2', 'balance-xor',
    '3', 'broadcast',
    '4', '802.3ad',
    '5', 'balance-tlb',
    '6', 'balance-alb',
  ]

  usage = """
  %prog [--nopeers]
  %prog --onlypeers
  %prog --unattend --bond=BOND --ip=ADDR --netmask=MASK --iface=IFACE1 --iface=IFACE2 [--iface=IFACE3 ...] [--gateway=GW] [--mode=MODE]"""

  description = """A script used to configure bonding on Linux machines, and to determine which interface groups (peers) are available for bonding.
------------------------------------------------------------------------------
https://github.com/sivel/bonding"""

  parser = OptionParser(description=description, usage=usage)

  peersGroup = OptionGroup(parser, 'Peers')
  peersGroup.add_option('--onlypeers', help='Only run the peers portion of this utility, to identify bonded peer interfaces', action='store_true')
  peersGroup.add_option('--nopeers',   help='Do not run the peers portion of this utility', action='store_true')
  parser.add_option_group(peersGroup)

  unattendGroup = OptionGroup(parser, 'Unattended')
  unattendGroup.add_option('--unattend', help='Whether to run this command unattended', action='store_true')
  unattendGroup.add_option('--bond',     help='The bonded master interface name. Required when using --unattend')
  unattendGroup.add_option('--ip',       help='The IP address to use in the bond. Required when using --unattend')
  unattendGroup.add_option('--netmask',  help='The Netmask to use in the bond. Required when using --unattend')
  unattendGroup.add_option('--iface',    help='The interfaces to be used in the bond, specify multiiple times for multiple interfaces. Required when using --unattend', action='append')
  unattendGroup.add_option('--gateway',  help='The default gateway to use for the system, if this is specified, the gateway and gateway dev will be updated. default: none')
  unattendGroup.add_option('--mode',     help='The bonding mode to be used. default: active-backup', choices=modes)
  parser.add_option_group(unattendGroup)

  (options, args) = parser.parse_args()

  if options.unattend:
    if not options.bond or not options.iface or not options.ip or not options.netmask:
      print 'You must supply a bond interface name, slave interfaces, IP Address and netmask'
      sys.exit(1)

    if not options.mode:
      options.mode = '1'

    extraOpts = ''
    if int(options.mode) == 4:
      extraOpts = ' lacp_rate=1'

    if options.mode in modeMap:
      options.mode = modeMap[options.mode]

    bondInfo = {
      'master':  options.bond,
      'slaves':  options.iface,
      'ipaddr':  options.ip,
      'netmask': options.netmask,
      'gateway': options.gateway,
      'mode':    options.mode,
      'opts':    extraOpts,
    }

    doBond({}, bondInfo)
    sys.exit(0)
  elif options.onlypeers:
    groups = peers(False)
    if groups:
      print 'Interface Groups:'
      for iface in sorted(groups.keys()):
        print ' '.join(sorted(groups[iface] + [iface]))
    else:
      print 'No interface groups exist'
    sys.exit(0)
  elif not options.onlypeers:
    groups = {}
    if not options.nopeers:
      print 'Scanning for bonding peers...'
      groups = peers(False)
      if groups:
        print '%sInterface Groups:' % GREEN
        for iface in sorted(groups.keys()):
          print ' '.join(sorted(groups[iface] + [iface]))
      else:
        result = confirm('%sNo interface groups exist, do you want to continue?%s' % (RED, RESET), False)
        if not result:
          sys.exit(0)
    doBond(groups)

  else:
    parser.print_help()

if __name__ == '__main__':
  handleArgs()

# vim:ts=2:sw=2:expandtab
