#!/bin/sh
set -e
srcdir="$(dirname $0)"
cd "$srcdir"
libtoolize && autoreconf --install --force
