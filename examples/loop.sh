#!/usr/bin/env bash
set -e

for i in {1..5}; do
    echo "loop: $i"
    echo "err: $i" >&2
    sleep 1
done
