
INCLUDES	= @GLIB_CFLAGS@ -I$(top_srcdir)/include \
                  -I$(top_srcdir)/libevent/include

bin_PROGRAMS	= brd picocoin blkscan blkstats rawtx

noinst_LIBRARIES= libnode.a

libnode_a_SOURCES=	\
	peerman.c	\
	peerman.h

brd_SOURCES=		\
	brd.c		\
	brd.h

brd_LDADD	= libnode.a ../lib/libccoin.a \
                  $(top_srcdir)/libevent/.libs/libevent.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@

picocoin_SOURCES=	\
	aes.c		\
	main.c		\
	net.c		\
	fakepoll.h	\
	picocoin.h	\
	wallet.c wallet.h

picocoin_LDADD	= libnode.a ../lib/libccoin.a \
                  $(top_srcdir)/libevent/.libs/libevent.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @JANSSON_LIBS@

blkscan_LDADD	= ../lib/libccoin.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@
blkstats_LDADD	= ../lib/libccoin.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@
rawtx_LDADD	= ../lib/libccoin.a \
		  @GLIB_LIBS@ @CRYPTO_LIBS@ @JANSSON_LIBS@
