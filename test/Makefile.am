if ENABLE_VALGRIND
    TESTS_ENVIRONMENT=$(LIBTOOL) --mode=execute valgrind --leak-check=full \
                        --leak-resolution=high --num-callers=40 \
                        --error-exitcode=1
endif

AM_CPPFLAGS	= -DTEST_SRCDIR=\"$(top_srcdir)/test\" \
		  -I$(top_srcdir)/include \
		  -I$(top_srcdir)/external/secp256k1/include

EXTRA_DIST	= \
	base58_encode_decode.json	\
	base58_keys_valid.json		\
	random.data			\
	blk0.json  blk120383.json  tx3e0dc3da.json \
	blk0.ser  blk120383.ser  tx3e0dc3da.ser \
	blks10.ser \
	hdr193000.ser tn_hdr35141.ser \
	tn_blk35133.ser wallet-basics.json \
	script_tests.json tx_valid.json tx_invalid.json

noinst_LIBRARIES= libtest.a

libtest_a_SOURCES= libtest.h libtest.c

noinst_PROGRAMS	= clist cstr coredefs hex hdkeys hashtab base58 fileio util \
		  keystore keyset bloom mbr \
		  message parr script-parse tx block blockfile blkdb script \
		  tx-valid wallet wallet-basics chain-verf

TESTS		= clist cstr coredefs hex hdkeys hashtab base58 fileio util \
		  keystore keyset bloom mbr \
		  message parr script-parse tx block blockfile blkdb script \
		  tx-valid wallet wallet-basics chain-verf

COMMON_LDADD	= libtest.a $(top_builddir)/lib/libccoin.la \
		  $(top_builddir)/external/secp256k1/libsecp256k1.la \
		  @CRYPTO_LIBS@ @GMP_LIBS@ @JANSSON_LIBS@ @MATH_LIBS@

base58_LDADD        = $(COMMON_LDADD)
blkdb_LDADD         = $(COMMON_LDADD)
block_LDADD         = $(COMMON_LDADD)
blockfile_LDADD 	= $(COMMON_LDADD)
bloom_LDADD         = $(COMMON_LDADD)
chain_verf_LDADD	= $(COMMON_LDADD)
clist_LDADD         = $(COMMON_LDADD)
cstr_LDADD		    = $(COMMON_LDADD)
coredefs_LDADD		    = $(COMMON_LDADD)
fileio_LDADD		= $(COMMON_LDADD)
hex_LDADD           = $(COMMON_LDADD)
hashtab_LDADD		= $(COMMON_LDADD)
hdkeys_LDADD		= $(COMMON_LDADD)
keyset_LDADD		= $(COMMON_LDADD)
keystore_LDADD		= $(COMMON_LDADD)
mbr_LDADD		= $(COMMON_LDADD)
message_LDADD		= $(COMMON_LDADD)
parr_LDADD		    = $(COMMON_LDADD)
script_LDADD		= $(COMMON_LDADD)
script_parse_LDADD	= $(COMMON_LDADD)
tx_LDADD            = $(COMMON_LDADD)
tx_valid_LDADD		= $(COMMON_LDADD)
util_LDADD		    = $(COMMON_LDADD) ../lib/libccoinnet.la
wallet_LDADD		= $(COMMON_LDADD)
wallet_basics_LDADD	= $(COMMON_LDADD)
