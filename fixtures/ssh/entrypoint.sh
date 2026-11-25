#!/bin/sh
set -eu

install -m 0600 /fixture/host_key /run/sshd/host_key
install -m 0644 /fixture/authorized_keys /run/sshd/authorized_keys
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
