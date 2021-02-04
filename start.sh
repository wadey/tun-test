#!/bin/sh

set -e -x

(
    sleep 1

    ip addr add 172.31.0.1/24 dev tun1
    ip link set dev tun1 mtu 1500
    ip link set dev tun1 txqueuelen 50000
    ip link set dev tun1 up
) &

exec ./tun-test "$@"
