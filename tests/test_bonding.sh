#!/bin/bash
#
# Run /home/vagrant/bonding.py to configure eth1 and eth2.
#
set -e

OS=${1:?'Error: Must pass os argument'}
BOND=${2:?'Error: Must pass bond interface argument'}
IP=${3:?'Error: Must pass IP address argument'}
IFACE1=${4:?'Error: Must pass interface 1 argument'}
IFACE2=${5:?'Error: Must pass interface 2 argument'}

DIR="/home/vagrant"
SCRIPT="${DIR}/bonding.py"
PYTHON=$(command -v python3 python2 python | head -n1)

function error() {
    echo "Error: $*" >&2
    exit 1
}


if [[ "x${PYTHON}" == "x" ]] || [[ ! -x "${PYTHON}" ]]; then
    error "Could not find python, python2, or python3 executable"
fi

if [[ ! -e "${SCRIPT}" ]]; then
    error "Did not find ${SCRIPT}"
fi


echo "Run ${OS} ${PYTHON} ${SCRIPT}"
echo "    with --onlypeers"
${PYTHON} "${SCRIPT}" --onlypeers | tee /tmp/${BOND}.onlypeers.log


echo "Run ${OS} ${PYTHON} ${SCRIPT}"
echo "    with ${BOND} ${IP} ${IFACE1} ${IFACE2}"
${PYTHON} "${SCRIPT}" --nopeers --unattend --bond=${BOND} \
                    --ip=${IP} --netmask=255.255.255.0 \
                    --iface=${IFACE1} --iface=${IFACE2}


echo "Activate ${BOND}"
case ${OS} in
    "centos7")
        systemctl restart NetworkManager
        sleep 2
        ifdown ${IFACE1}
        ifdown ${IFACE2}
        ifup ${IFACE1}
        ifup ${IFACE2}
        ;;
    "centos6")
        ifup ${BOND}
        ;;
    "ubuntu18"|"ubuntu16")
        ifup ${IFACE1}
        ifup ${IFACE2}
        ifup ${BOND}
        ;;
    *)
        error "Unsupported OS: ${OS}"
esac


echo "Wait for ${BOND} interface to be up (may take 60+ seconds)"
while ! ip addr show dev ${BOND} | grep -qi 'state up';
do
    sleep 3;
done;

echo;
ip addr show dev ${BOND}
ip addr show dev ${IFACE1}
ip addr show dev ${IFACE2}

echo;
cat /proc/net/bonding/${BOND}


echo
echo
echo "##########"
echo "Verify tests"
echo "##########"
echo
echo "Verify bonding test passed."
if ! grep "Slave Interface: ${IFACE1}" /proc/net/bonding/${BOND}; then
    echo "Did not find slave interface ${IFACE1} on ${BOND}"
    exit 1
fi
if ! grep "Slave Interface: ${IFACE2}" /proc/net/bonding/${BOND}; then
    echo "Did not find slave interface ${IFACE2} on ${BOND}"
    exit 1
fi
echo "bonding test passed!"
echo


echo "Verify onlypeers test passed:"
if [[ $(grep -A1 'Interface Groups' /tmp/${BOND}.onlypeers.log | wc -w) == '4' ]]; then
    # Interface Groups:
    # eth3 eth4
    echo "onlypeers test passed!"
else
    echo "onlypeers test failed"
    exit 1
fi
