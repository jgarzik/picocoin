##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

bin_PROGRAMS	= picocoin

noinst_LIBRARIES= libccoin.a

libccoin_a_SOURCES=	\
	address.c	\
	address.h	\
	base58.c base58.h \
	bignum.c	\
	blkdb.c blkdb.h	\
	buffer.h	\
	buint.c buint.h	\
	core.c core.h	\
	coredefs.c	\
	coredefs.h	\
	dns.c		\
	key.c key.h	\
	mbr.c mbr.h	\
	message.c	\
	message.h	\
	serialize.c	\
	serialize.h	\
	util.c util.h

picocoin_SOURCES=	\
	aes.c		\
	main.c		\
	net.c		\
	peerman.c	\
	peerman.h	\
	picocoin.h	\
	wallet.c wallet.h

picocoin_LDADD	= libccoin.a @GLIB_LIBS@ @CRYPTO_LIBS@ @EVENT_LIBS@

EXTRA_DIST	= autogen.sh

