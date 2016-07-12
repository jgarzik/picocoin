
AM_CPPFLAGS	= -I$(top_srcdir)/include

bin_PROGRAMS	= brd picocoin blkscan blkstats rawtx

brd_SOURCES=		\
	brd.c		\
	brd.h

brd_LDADD	= ../lib/libccoin.la ../lib/libccoinnet.la \
		  @CRYPTO_LIBS@ @GMP_LIBS@ @EVENT_LIBS@

picocoin_SOURCES=	\
	main.c		\
	picocoin.h	\
	aes.c           \
        wallet.c wallet.h

picocoin_LDADD	= ../lib/libccoin.la ../lib/libccoinnet.la \
		  @CRYPTO_LIBS@ @GMP_LIBS@ @ARGP_LIBS@ \
		  @EVENT_LIBS@ @JANSSON_LIBS@

blkscan_LDADD	= ../lib/libccoin.la \
		  @CRYPTO_LIBS@ @GMP_LIBS@ @ARGP_LIBS@
blkstats_LDADD	= ../lib/libccoin.la \
		  @CRYPTO_LIBS@ @GMP_LIBS@ @ARGP_LIBS@
rawtx_LDADD	= ../lib/libccoin.la \
		  @CRYPTO_LIBS@ @GMP_LIBS@ @ARGP_LIBS@ @JANSSON_LIBS@
