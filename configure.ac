#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([pam_ldap2krb], [0.1], [kazimsarikaya@sanaldiyar.com])
AM_INIT_AUTOMAKE
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/pam_ldap2krb.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lconfuse':
AC_CHECK_LIB([confuse], [cfg_init])
# FIXME: Replace `main' with a function in `-lkrb5':
AC_CHECK_LIB([krb5], [krb5_init_secure_context])
# FIXME: Replace `main' with a function in `-llber':
AC_CHECK_LIB([lber], [ber_free])
# FIXME: Replace `main' with a function in `-lldap':
AC_CHECK_LIB([ldap], [ldap_initialize])
# FIXME: Replace `main' with a function in `-lpam':
AC_CHECK_LIB([pam], [pam_get_user])

# Checks for header files.
AC_CHECK_HEADERS([memory.h stdlib.h ldap.h confuse.h krb5.h security/pam_appl.h security/pam_modules.h security/pam_ext.h],[],[echo "missing header, can not continue!"; exit -1;])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 src/Makefile])
AC_OUTPUT
