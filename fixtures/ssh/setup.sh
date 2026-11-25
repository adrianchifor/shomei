#!/bin/sh
set -eu

if [ $# -ne 1 ]; then
    printf 'Usage: sh fixtures/ssh/setup.sh SSH_PUBLIC_KEY\n' >&2
    exit 2
fi

read -r key_type key_data _ <"$1" || [ -n "$key_data" ]
case "$key_type" in
    ssh-*|ecdsa-sha2-*|sk-*) ;;
    *) printf 'Expected an OpenSSH public key file.\n' >&2; exit 2 ;;
esac
ssh-keygen -l -f "$1" >/dev/null
umask 077
mkdir -p local/ssh
if [ ! -f local/ssh/host_key ]; then
    ssh-keygen -q -t ed25519 -N '' -f local/ssh/host_key
fi
ssh-keygen -y -f local/ssh/host_key >local/ssh/host_key.pub
printf '%s %s\n' "$key_type" "$key_data" >local/ssh/authorized_keys
chmod 0644 local/ssh/authorized_keys
printf 'deploy %s\n' "$(cat local/ssh/host_key.pub)" >local/ssh/known_hosts
