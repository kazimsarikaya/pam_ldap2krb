Name:		pam_ldap2krb
Version:	0.1
Release:	1%{?dist}
Summary:	Password Migration PAM Module for ldap to ldap+kerberos

#Group:		security
License:	GPLv3
URL:		https://git.sanaldiyar.com/gitweb.cgi/pam_ldap2krb.git
# The source for this package was pulled from upstrams's vcs. Use the
# following commands to generate the tarball:
#  git clone https://git.sanaldiyar.com/gitweb.cgi/pam_ldap2krb.git
#  ./autogen.sh
#  ./configure
#  make distcheck
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	pam-devel libconfuse-devel krb5-devel openldap-devel
#Requires:	pam libconfuse krb5-workstation openldap

%description
While migration from LDAP to LDAP+Kerberos, password migration is difficult
because of differences between ldap and kerberos password store format. This
pam module updates kerberos password if ldap password accepted for user.

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
%make_install

%post
/sbin/ldconfig
%postun
/sbin/ldconfig

%files
%doc README
%{_sysconfdir}/pam_ldap2krb.conf
%{_libdir}/security/pam_ldap2krb.so


%changelog
* Tue Mar 11 2014 Kazım SARIKAYA <kazimsarikaya@sanaldiyar.com> - 0.1
- Initial rpm release
