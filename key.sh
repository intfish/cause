#!/usr/bin/env bash
set -e

if [ -z "$1" ]; then
	echo "Usage: $0 <secret>" >&2
	exit 1
fi

HASH=$(mkpasswd -m yescrypt "$1")
KEYID=$(head -c 4 /dev/urandom | xxd -p)
echo "${KEYID}:${HASH}"
