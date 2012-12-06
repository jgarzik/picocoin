
INCLUDES	= @GLIB_CFLAGS@ -I$(top_srcdir)/include

bin_PROGRAMS	= brd picocoin

brd_SOURCES=		\
	brd.c		\
	brd.h

brd_LDADD	= ../lib/libccoin.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @EVENT_LIBS@

picocoin_SOURCES=	\
	aes.c		\
	main.c		\
	net.c		\
	fakepoll.h	\
	peerman.c	\
	peerman.h	\
	picocoin.h	\
	wallet.c wallet.h

picocoin_LDADD	= ../lib/libccoin.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @EVENT_LIBS@ @JANSSON_LIBS@

