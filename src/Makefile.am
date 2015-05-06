
AM_CPPFLAGS	= -I$(top_srcdir)/include

bin_PROGRAMS	= brd picocoin blkscan blkstats rawtx

noinst_LIBRARIES= libnode.a

libnode_a_SOURCES=	\
	peerman.c	\
	peerman.h

brd_SOURCES=		\
	brd.c		\
	brd.h

brd_LDADD	= libnode.a ../lib/libccoin.a \
		  @CRYPTO_LIBS@ @EVENT_LIBS@

picocoin_SOURCES=	\
	aes.c		\
	main.c		\
	net.c		\
	fakepoll.h	\
	picocoin.h	\
	wallet.c wallet.h

picocoin_LDADD	= libnode.a ../lib/libccoin.a \
		  @CRYPTO_LIBS@ @ARGP_LIBS@ \
		  @EVENT_LIBS@ @JANSSON_LIBS@

blkscan_LDADD	= ../lib/libccoin.a \
		  @CRYPTO_LIBS@ @ARGP_LIBS@
blkstats_LDADD	= ../lib/libccoin.a \
		  @CRYPTO_LIBS@ @ARGP_LIBS@
rawtx_LDADD	= ../lib/libccoin.a \
		  @CRYPTO_LIBS@ @ARGP_LIBS@ @JANSSON_LIBS@
