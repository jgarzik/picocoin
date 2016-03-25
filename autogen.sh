#!/bin/sh
set -e
srcdir="$(dirname $0)"
cd "$srcdir"

if which glibtoolize
then
	glibtoolize && autoreconf --install --force
else
	libtoolize && autoreconf --install --force
fi

