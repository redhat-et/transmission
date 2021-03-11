Name:          transmission-agent
Version:       0.1
Release:       1%{?dist}
Summary:       An experimental device management agent for ostree-based Linux operating systems
License:       Apache License, Version 2.0
URL:           https://github.com/fzdarsky/transmission
Source0:       https://github.com/fzdarsky/transmission/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildArch: noarch
Requires: python3-pyyaml

%description
Transmission is an experimental device management agent for ostree-based Linux operating systems.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install transmission.py %{buildroot}/usr/bin/transmission
chmod +x %{buildroot}/usr/bin/transmission
mkdir -p %{buildroot}%{_unitdir}
install systemd/transmission* %{buildroot}%{_unitdir}/
mkdir -p %{buildroot}%{_sharedstatedir}/transmission
mkdir -p %{buildroot}%{_sysconfdir}/issue.d/
ln -s /run/transmission-banner %{buildroot}%{_sysconfdir}/issue.d/transmission.issue

%files
%license LICENSE
%{_sharedstatedir}/transmission
%{_bindir}/transmission
%{_sysconfdir}/issue.d/transmission.issue
%{_unitdir}/*

%changelog
* Thu Mar 11 2021 Frank Zdarsky <fzdarsky@redhat.com> 0.1-1
- Initial package
