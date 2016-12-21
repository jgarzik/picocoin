
AM_CPPFLAGS = -I$(top_srcdir)/include \
            -I$(top_srcdir)/external/secp256k1/include

bin_PROGRAMS	= brd picocoin blkscan blkstats rawtx

brd_SOURCES=		\
	brd.c		\
	brd.h

brd_LDADD	= $(top_builddir)/lib/libccoin.la \
		  $(top_builddir)/lib/libccoinnet.la \
		  @GMP_LIBS@ @EVENT_LIBS@

picocoin_SOURCES=	\
	main.c		\
	picocoin.h	\
	wallet.c wallet.h

picocoin_LDADD	= $(top_builddir)/lib/libccoin.la \
		  $(top_builddir)/lib/libccoinnet.la \
		  $(top_builddir)/lib/libccoinaes.la \
		  @GMP_LIBS@ @ARGP_LIBS@ \
		  @EVENT_LIBS@ @JANSSON_LIBS@

blkscan_LDADD	= $(top_builddir)/lib/libccoin.la \
		  @GMP_LIBS@ @ARGP_LIBS@
blkstats_LDADD	= $(top_builddir)/lib/libccoin.la \
		  @GMP_LIBS@ @ARGP_LIBS@
rawtx_LDADD	= $(top_builddir)/lib/libccoin.la \
		  @GMP_LIBS@ @ARGP_LIBS@ @JANSSON_LIBS@
