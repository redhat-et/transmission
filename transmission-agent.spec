Name:          transmission-agent
Version:       0.1.7
Release:       1%{?dist}
Summary:       An experimental device management agent for ostree-based Linux operating systems
License:       Apache License, Version 2.0
URL:           https://github.com/redhat-et/transmission
Source0:       https://github.com/redhat-et/transmission/archive/%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildArch: noarch
Requires: python3-pyyaml

%description
Transmission is an experimental device management agent for ostree-based Linux operating systems.

%prep
%autosetup -n transmission-%{version}

%build

%install
mkdir -p %{buildroot}/usr/bin/
install -m 0755 transmission.py %{buildroot}/usr/bin/transmission
mkdir -p %{buildroot}%{_unitdir}
install systemd/transmission* %{buildroot}%{_unitdir}/
mkdir -p %{buildroot}%{_sharedstatedir}/transmission
mkdir -p %{buildroot}%{_sysconfdir}/issue.d/
ln -s /run/transmission-banner %{buildroot}%{_sysconfdir}/issue.d/transmission.issue

%files
%license LICENSE
%{_sharedstatedir}/transmission
/usr/bin/transmission
%{_sysconfdir}/issue.d/transmission.issue
%{_unitdir}/*

%changelog
* Fri Apr 8 2022 Frank Zdarsky <fzdarsky@redhat.com> 0.1.7-1
- Added support for managing containers via podman play kube
* Tue Aug 17 2021 Frank Zdarsky <fzdarsky@redhat.com> 0.1.6-1
- Added subscription id and insights id
* Mon Aug 2 2021 Frank Zdarsky <fzdarsky@redhat.com> 0.1.5-1
- Added fetching from GitHub
* Wed Mar 31 2021 Frank Zdarsky <fzdarsky@redhat.com> 0.1.4-1
- Added a few symlinked dirs to sync allow list
* Thu Mar 24 2021 Frank Zdarsky <fzdarsky@redhat.com> 0.1.3-1
- Added rollback, improved handling of systemd and logging
* Thu Mar 11 2021 Frank Zdarsky <fzdarsky@redhat.com> 0.1-1
- Initial package
