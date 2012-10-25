##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

bin_PROGRAMS	= picocoin

picocoin_SOURCES=	\
	aes.c		\
	coredefs.h	\
	core.c core.h	\
	dns.c		\
	key.c key.h	\
	main.c		\
	message.c	\
	message.h	\
	picocoin.h	\
	serialize.c	\
	serialize.h	\
	wallet.c wallet.h

picocoin_LDADD	= @GLIB_LIBS@ @CRYPTO_LIBS@

EXTRA_DIST	= autogen.sh

