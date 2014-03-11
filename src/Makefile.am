moduledir = $(libdir)/security

module_LTLIBRARIES = pam_ldap2krb.la
pam_ldap2krb_la_SOURCES = pam_ldap2krb.c
pam_ldap2krb_la_CPPFLAGS = -fPIC -DPIC
pam_ldap2krb_la_LIBADD = -lpam -lldap -llber -lkrb5 -lconfuse
pam_ldap2krb_la_LDFLAGS = -rdynamic -shared -module -avoid-version
