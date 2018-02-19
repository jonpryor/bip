#!/bin/sh
# Create /run/sysconfig/bip from default configuration file, for
# bip-config.service

# BIP_DEFAULT_CONFIG environment variable can be defined by packagers in a
# drop-in override of bip-config.service unit
if [ -n "${BIP_DEFAULT_CONFIG}" ]; then
    # try some default paths
    if [ -r /etc/default/bip ]; then
        BIP_DEFAULT_CONFIG=/etc/default/bip
        . "${BIP_DEFAULT_CONFIG}"
    elif [ -r /etc/sysconfig/bip ]; then
        BIP_DEFAULT_CONFIG=/etc/sysconfig/bip
        . "${BIP_DEFAULT_CONFIG}"
    fi
else
    . "${BIP_DEFAULT_CONFIG}"
fi

ENABLED=${ENABLED:-1}

mkdir -p /run/sysconfig
{
echo ENABLED=${ENABLED}
DAEMON_HOME=${DAEMON_HOME:-/var/lib/bip}
DAEMON_CONFIG=${DAEMON_CONFIG:-/etc/bip/bip.conf}
echo "DAEMON_ARGS=${DAEMON_ARGS:--f '${DAEMON_CONFIG}' -s '${DAEMON_HOME}'}"
} > /run/sysconfig/bip

if [ ${ENABLED} = 0 ]; then
    echo "INFO: BIP is explicitely disabled (ENABLED == 0) in" \
         "'${BIP_DEFAULT_CONFIG}'."
else
    if [ -n "${DAEMON_USER}" -o -n "${DAEMON_GROUP}" ]; then
        echo "ERROR: Using systemd, DAEMON_USER and DAEMON_GROUP could not" \
             "be defined using the default configuration file. A drop-in" \
             "override of bip-config.service unit need to be created instead."
        exit 1
    fi
fi
