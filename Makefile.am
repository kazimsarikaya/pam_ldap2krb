SUBDIRS = src conf

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = pam_ldap2krb.spec

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/security/pam_ldap2krb.la

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/security/pam_ldap2krb.so

rpmbuild: distcheck
	-rm -fr _rpmbuild
	-mkdir -p $(top_builddir)/_rpmbuild/{SRPMS,RPMS,SPECS,SOURCES}
	-rm -fr $(top_builddir)/_rpmbuild/SOURCES/*
	cp $(top_builddir)/pam_ldap2krb.spec $(top_builddir)/_rpmbuild/SPECS
	cp  $(top_builddir)/pam_ldap2krb-$(VERSION).tar.gz  $(top_builddir)/_rpmbuild/SOURCES/
	rpmbuild --define "_topdir $(shell pwd)/_rpmbuild" -ba $(top_builddir)/_rpmbuild/SPECS/pam_ldap2krb.spec
	find  $(top_builddir)/_rpmbuild -name "*.rpm" -exec cp {} . \;
	-rm -fr _rpmbuild

clean-local:
	rm -fr *.rpm _rpmbuild $(top_builddir)/pam_ldap2krb-$(VERSION).tar.gz
