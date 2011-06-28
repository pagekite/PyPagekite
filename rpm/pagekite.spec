Name:           pagekite
Version:        0.3.19
Release:	0%{?dist}
Summary:        PageKite is a system for running publicly visible servers (generally web servers) on machines without a direct connection to the Internet behind restrictive firewalls.
Group:          Applications/System
License:        GPLv2+
URL:            https://pagekite.net/
Source0:        pagekite-0.3.19.tar.gz
Source1:	pagekite.init
Source2:	pagekite.sysconfig
Source3:	pagekite.logrotate
Source4:	README.fedora
Source5:	pagekite.rc.sample
Source6:	local.rc.sample
Source7:	frontend.rc.sample
Source8:	pagekite.net.ca_cert
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:	noarch

BuildRequires:  python python-devel
Requires:       pyOpenSSL

%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

%description
PageKite is a system for running publicly visible servers (generally web servers) on machines without a direct connection to the Internet, such as mobile devices or computers behind restrictive firewalls.
Without PageKite, this is a vexingly difficult problem. In spite of the fact that powerful computers and high-speed Internet connections are now the norm in many places, technicalities generally conspire to make servers on home or mobile machines largely unreachable from the wider Internet - and therefore useless.
These technicalities - firewalls, NAT, IP addresses, DNS - are the problems PageKite simplifies and solves.

%prep
%setup -q -n pagekite-%{version}

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}

%{__python} setup.py install -O1 --skip-build --root=%{buildroot}

install -d %{buildroot}/%{_bindir}
install -d %{buildroot}/%{_initrddir}
install -d %{buildroot}/%{_sysconfdir}/logrotate.d
install -d %{buildroot}/%{_sysconfdir}/sysconfig
install -d %{buildroot}/%{_sysconfdir}/pagekite
install -d %{buildroot}/%{_localstatedir}/log/pagekite

install -p -m 755 %{SOURCE5} %{buildroot}/%{_sysconfdir}/pagekite/pagekite.rc
install -p -m 755 %{SOURCE7} %{buildroot}/%{_sysconfdir}/pagekite/frontend.rc
install -p -m 600 %{SOURCE6} %{buildroot}/%{_sysconfdir}/pagekite/local.rc
install -p -m 755 %{SOURCE8} %{buildroot}/%{_sysconfdir}/pagekite/pagekite.net.ca_cert
install -p -m 755 %{SOURCE1} %{buildroot}/%{_initrddir}/pagekite
install -p -m 644 %{SOURCE2} %{buildroot}/%{_sysconfdir}/sysconfig/pagekite
install -p -m 644 %{SOURCE3} %{buildroot}/%{_sysconfdir}/logrotate.d/pagekite

touch %{buildroot}/%{_localstatedir}/log/pagekite/pagekite.log

# FC-4 and earlier won't create these automatically; create them here
# so that the %exclude below doesn't fail
touch %{buildroot}/%{_bindir}/pagekite.pyc
touch %{buildroot}/%{_bindir}/pagekite.pyo

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add pagekite
/sbin/service pagekite stop
exit 0

%preun
if [ $1 = 0 ]; then
  /sbin/service pagekite stop > /dev/null 2>&1
  /sbin/chkconfig --del pagekite
fi
exit 0

%files
%defattr(-,root,root,-)
%doc pagekite.rc.sample local.rc.sample frontend.rc.sample
%doc README.fedora README.md setup.py 
%doc HISTORY.txt agpl-3.0.txt

%{_bindir}/pagekite.py
%exclude %{_bindir}/pagekite.py[co]

#%{_datadir}/pagekite
#%{python_sitelib}/pagekite/

%config(noreplace) %{_sysconfdir}/pagekite/pagekite.rc
%config(noreplace) %{_sysconfdir}/pagekite/frontend.rc
%config(noreplace) %{_sysconfdir}/pagekite/local.rc
%config(noreplace) %{_sysconfdir}/pagekite/pagekite.net.ca_cert
%config(noreplace) %{_sysconfdir}/logrotate.d/pagekite
%config(noreplace) %{_sysconfdir}/sysconfig/pagekite

%ghost %{_localstatedir}/log/pagekite

%{_initrddir}/pagekite

%changelog
* Tue May 3 2011 Edvin Dunaway <edvin@eddinn.net> - updated pagekite binary to stable 0.3.19-0
* Mon May 2 2011 Edvin Dunaway <edvin@eddinn.net> - 0.3.18-0 - Initial build
