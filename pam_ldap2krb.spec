Name:		pam_ldap2krb
Version:	0.1
Release:	1%{?dist}
Summary:	Password Migration PAM Module for ldap to ldap+kerberos

Group:		security
License:	GPLv3
URL:		https://git.sanaldiyar.com/gitweb.cgi/pam_ldap2krb.git
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	pam-devel libconfuse-devel krb5-devel openldap-devel
Requires:	pam libconfuse krb5-workstation openldap

%description
Password migration pam module for ldap to ldap+kerberos authentication system.
Passwords will be created in kerberos if user name and password are validated with
existing ldap server. A configuration file is  /etc/pam_ldap2krb.conf

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}


%files
%doc README
%{_sysconfdir}/*
%{_libdir}/*


%changelog
* Tue Mar 11 2014 Kazım SARIKAYA <kazimsarikaya@sanaldiyar.com>
- Initial rpm release
