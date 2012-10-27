##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

bin_PROGRAMS	= picocoin

noinst_LIBRARIES= libccoin.a

libccoin_a_SOURCES=	\
	buffer.h	\
	coredefs.c	\
	coredefs.h

picocoin_SOURCES=	\
	aes.c		\
	base58.c base58.h \
	bignum.c	\
	core.c core.h	\
	dns.c		\
	key.c key.h	\
	main.c		\
	message.c	\
	message.h	\
	net.c		\
	picocoin.h	\
	serialize.c	\
	serialize.h	\
	util.c util.h	\
	wallet.c wallet.h

picocoin_LDADD	= libccoin.a @GLIB_LIBS@ @CRYPTO_LIBS@

EXTRA_DIST	= autogen.sh

