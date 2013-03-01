Building `picocoin` on OS X
===========================

Instructions by @[colindean](http://github.com/colindean).

Note that these instructions were written on OS X 10.8. They may apply to 
earlier versions of OS X. Unsure? Try!

Dependencies
------------

This guide assumes usage of [Homebrew](http://mxcl.github.com/homebrew/) or
[MacPorts](http://www.marcports.org) for installing dependencies.

You will need to install `glib` and `OpenSSL` in order to build *libccoin*, and
those plus `libevent` and `jansson` to build *picocoin*.

Install these packages. It will take a few minutes.

    brew install glib openssl libevent jansson

or

    sudo port install glib2 openssl libevent jansson

You may also need to install some development dependencies, if you have not
already installed them for other projects.

    brew install autoconf automake

or

    sudo port install autoconf automake pkgconfig

Building
--------

Now, you can build!

    ./autogen.sh
    ./configure CPPFLAGS="-I`brew --prefix openssl`/include"
    make

if you used Homebrew, or:

    ./autogen.sh
    ./configure CPPFLAGS="-I /opt/local/include -L /opt/local/lib"
    make

if you used MacPorts.

You should also run `make check` in order to run tests. This is a vital step
early in the development of `picocoin`.

You can install it if you want with `make install`. It will be installed to 
`/usr/local/picocoin`.

The `picocoin` binary will be in `./src`.

Running
-------

To ensure that at least the basics compiled correctly, execute a command:

    src/picocoin list-settings

You should see some output formatted in JSON, and looking like this:

    {
      "wallet": "picocoin.wallet",
      "peers": "picocoin.peers",
      "chain": "bitcoin"
    }

If that works, `picocoin` is ready for use.
