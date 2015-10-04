dnl Process this file with autoconf 2.52+ to produce a configure script.
dnl
dnl Copyright (C) 2001 Philipp Rumpf
dnl Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_INIT(picocoin, 0.1git, [Jeff Garzik <jgarzik@exmulti.com>])
AC_PREREQ(2.60)
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([picocoin-config.h])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

AC_CANONICAL_HOST

dnl Checks for programs
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_GCC_TRADITIONAL

dnl Checks for header files.
AC_HEADER_STDC
dnl AC_CHECK_HEADERS(sys/ioctl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
AC_TYPE_SIZE_T

dnl TODO: AC_SYS_LARGEFILE does not produce O_LARGEFILE on 64-bit Fedora Linux?
AC_SYS_LARGEFILE

AH_VERBATIM([_LARGEFILE64_SOURCE],
[/* Enable LFS extensions on systems that have them.  */
#ifndef _LARGEFILE64_SOURCE
# define _LARGEFILE64_SOURCE 1
#endif])

case "${host}" in
	*-*-darwin*)
		AH_VERBATIM([O_LARGEFILE],
		[/* OSX naturally supports 64-bit files */
		#ifndef O_LARGEFILE
		# define O_LARGEFILE 0
		#endif])
		;;
esac

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------

AC_CHECK_LIB(m, log, MATH_LIBS=-lm,
  [AC_MSG_ERROR([Missing required libm])])
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto,
  [AC_MSG_ERROR([Missing required libcrypto])])
AC_CHECK_LIB(event_core, event_base_new, EVENT_LIBS=-levent_core,
  [AC_MSG_ERROR([Missing required libevent])])
AC_CHECK_LIB(jansson, json_loads, JANSSON_LIBS=-ljansson,
  [AC_MSG_ERROR([Missing required libjansson])])
AC_CHECK_LIB(argp, argp_parse, ARGP_LIBS=-lARGP)

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------
AC_CHECK_FUNCS(fdatasync memmem strndup mkstemp)

dnl -----------------
dnl Configure options
dnl -----------------

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AC_SUBST(MATH_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(EVENT_LIBS)
AC_SUBST(JANSSON_LIBS)
AC_SUBST(ARGP_LIBS)

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	include/Makefile
	include/ccoin/Makefile
	lib/Makefile
	src/Makefile
	test/Makefile
	])
AC_OUTPUT

