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
AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([main.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([picocoin-config.h])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_GCC_TRADITIONAL

dnl Checks for header files.
AC_HEADER_STDC
dnl AC_CHECK_HEADERS(sys/ioctl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
dnl AC_CHECK_LIB(gssrpc, gssrpc_svc_register, GSSRPC_LIBS=-lgssrpc, exit 1)

dnl AC_CHECK_LIB(db-4.3, db_create, DB4_LIBS=-ldb-4.3)
dnl AC_CHECK_LIB(db-4.4, db_create, DB4_LIBS=-ldb-4.4)
dnl AC_CHECK_LIB(db-4.5, db_create, DB4_LIBS=-ldb-4.5)
dnl AC_CHECK_LIB(db-4.6, db_create, DB4_LIBS=-ldb-4.6)
dnl AC_CHECK_LIB(db-4.7, db_create, DB4_LIBS=-ldb-4.7)
dnl AC_CHECK_LIB(db-4.8, db_create, DB4_LIBS=-ldb-4.8)
dnl AC_CHECK_LIB(db-4.9, db_create, DB4_LIBS=-ldb-4.9)
dnl AC_CHECK_LIB(db-5.0, db_create, DB4_LIBS=-ldb-5.0)
dnl AC_CHECK_LIB(db-5.1, db_create, DB4_LIBS=-ldb-5.1)
dnl AC_CHECK_LIB(db-5.2, db_create, DB4_LIBS=-ldb-5.2)

dnl if test "x$DB4_LIBS" = x; then
dnl 	AC_MSG_ERROR([Missing required libdb 4.x])
dnl fi

AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto)
dnl AC_CHECK_LIB(event, event_base_new, EVENT_LIBS=-levent,
dnl   [AC_MSG_ERROR([Missing required libevent])])

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------
AC_CHECK_FUNCS(fdatasync)

dnl -----------------
dnl Configure options
dnl -----------------

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AM_PATH_GLIB_2_0(2.0.0, , exit 1)

dnl AC_SUBST(GSSRPC_LIBS)
dnl AC_SUBST(DB4_LIBS)
dnl AC_SUBST(EVENT_LIBS)
AC_SUBST(CRYPTO_LIBS)
dnl AC_SUBST(ARGP_LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
