Building `picocoin` on OS X
===========================

Instructions by @[colindean](http://github.com/colindean).



Dependencies
------------

This guide assumes usage of [Homebrew](http://brew.sh) or
[MacPorts](https://www.macports.org) for installing dependencies.

You will need to install `OpenSSL` in order to build *libccoin*, and
those plus `libevent` and `jansson` to build *picocoin*.

Install these packages. It will take a few minutes.

    brew install autoconf automake argp-standalone jansson libevent openssl

or

    sudo port install autoconf automake argp-standalone jansson libevent pkgconfig openssl


Building
--------

Homebrew

    ./autogen.sh
    ./configure CPPFLAGS="-I`brew --prefix openssl`/include"
    make

MacPorts

    ./autogen.sh
    ./configure CPPFLAGS="-I /opt/local/include -L /opt/local/lib"
    make


You should also run `make check` in order to run tests. This is a vital step
early in the development of `picocoin`.

You can install it if you want with `make install`. It will be installed to 
`/usr/local/picocoin`.

The `picocoin` binary will be in `./src`.

Running
-------

To ensure that at least the basics compiled correctly, execute a command:

    src/picocoin list-settings

You should see output formatted in JSON,

    {
      "wallet": "picocoin.wallet",
      "chain": "bitcoin",
      "net.connect.timeout": "11",
      "peers": "picocoin.peers",
      "blkdb": "picocoin.blkdb"
    }

If that works, `picocoin` is ready for use.
