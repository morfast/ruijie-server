#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([rjserver], [1.0], [https://github.com/morfast/ruijie-server])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([rjserver.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap],[pcap_sendpacket])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AM_GNU_GETTEXT_VERSION(0.16.1)
