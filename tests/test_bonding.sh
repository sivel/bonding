#!/bin/bash
#
# Run /home/vagrant/bonding.py to configure eth1 and eth2.
#
set -e

echo "test_bonding Version 1.0.0"

OS=${1:?'Error: Must pass os argument'}
BOND=${2:?'Error: Must pass bond interface argument'}
IP=${3:?'Error: Must pass IP address argument'}
IFACE1=${4:?'Error: Must pass interface 1 argument'}
IFACE2=${5:?'Error: Must pass interface 2 argument'}

DIR="/home/vagrant"
SCRIPT="${DIR}/bonding.py"
PYTHON=$(command -v python3 python2 python /usr/libexec/platform-python | head -n1)

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
     "centos8"|"centos7")
        # Do nothing. The script brings the interface up with nmcli.
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
COUNT=0
while ! ip addr show dev ${BOND} | grep -qi 'state up';
do
    sleep 3;
    if [[ ${COUNT} -gt 20 ]]; then
        echo "Timed out"
        break
    else
        COUNT=$(($COUNT + 1))
        echo -n "."
    fi
done;

echo;
ip addr show dev ${BOND}
ip addr show dev ${IFACE1}
ip addr show dev ${IFACE2}

echo;
cat /proc/net/bonding/${BOND}


echo
echo
echo "TEST: ##########"
echo "TEST: Verify ${OS} tests"
echo "TEST: ##########"
echo "TEST"
echo "TEST: Verify ${OS} bonding ${BOND} test passed:"
if ! grep "Slave Interface: ${IFACE1}" /proc/net/bonding/${BOND}; then
    echo "TEST: FAILED: Did not find slave interface ${IFACE1} on ${BOND}"
    exit 1
fi
if ! grep "Slave Interface: ${IFACE2}" /proc/net/bonding/${BOND}; then
    echo "TEST: FAILED: Did not find slave interface ${IFACE2} on ${BOND}"
    exit 1
fi
echo "TEST: ${OS} bonding ${BOND} test passed!"
echo "TEST"


echo "TEST: Verify ${OS} onlypeers test passed:"
# Good
#     Done
#     Interface Groups:
#     eth3 eth4
# Bad
#     Done
#     No interface groups exist
if [[ $(grep -A1 'Interface Groups' /tmp/${BOND}.onlypeers.log | wc -w) == '4' ]]; then
    grep -A1 'Interface Groups' /tmp/${BOND}.onlypeers.log
    echo "TEST: ${OS} onlypeers test passed!"
else
    echo "TEST: FAILED ${OS} onlypeers test. Did not find Interface Group with 2 interfaces."
    exit 1
fi
echo "TEST"
