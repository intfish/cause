#!/usr/bin/env bash
set -e

for i in {1..10}; do
    echo "loop: $i"
    echo "err: $i" >&2
done
