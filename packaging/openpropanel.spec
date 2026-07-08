# RPM spec for Open ProPanel. This packages a *prebuilt* static binary (Go with
# CGO disabled), which keeps the build reproducible and network-free inside
# rpmbuild. Build the binary first with `make build`, then `make rpm`.
#
#   Source0: the linux/amd64 openpropanel binary  (staged by the Makefile)
#   Source1: the systemd unit                 (packaging/openpropanel.service)

Name:           openpropanel
Version:        %{?_version}%{!?_version:0.1.0}
Release:        1%{?dist}
Summary:        Open-source server control panel (cPanel alternative)

License:        MIT
URL:            https://github.com/openpropanel/openpropanel
BuildArch:      x86_64

Source0:        openpropanel
Source1:        openpropanel.service

# Needed for the %systemd_* scriptlet macros used below.
BuildRequires:  systemd-rpm-macros

# Runtime services Open ProPanel drives.
Requires:       httpd
Requires:       mod_ssl
Requires:       php-fpm
# NOTE: certbot lives in EPEL. Enable it first:  dnf install -y epel-release
Requires:       certbot
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Open ProPanel is a lightweight, single-binary control panel for managing a web
server: add domains and subdomains, auto-generate Apache virtual hosts, switch
PHP versions per site, and issue Let's Encrypt certificates — all from a clean
web UI. It ships as one self-contained binary with the UI embedded.

%prep
# Nothing to unpack: we package a prebuilt binary.

%install
rm -rf %{buildroot}
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/openpropanel
# Point the unit at the packaged binary location (%{_bindir}, i.e. /usr/bin).
install -d %{buildroot}%{_unitdir}
sed 's|/usr/local/bin/openpropanel|%{_bindir}/openpropanel|' %{SOURCE1} \
    > %{buildroot}%{_unitdir}/openpropanel.service
install -d -m 0700 %{buildroot}%{_sharedstatedir}/openpropanel
install -d -m 0755 %{buildroot}%{_sysconfdir}/openpropanel

%files
%{_bindir}/openpropanel
%{_unitdir}/openpropanel.service
%dir %attr(0700,root,root) %{_sharedstatedir}/openpropanel
%dir %{_sysconfdir}/openpropanel

%post
%systemd_post openpropanel.service
if [ $1 -eq 1 ]; then
    # First install: create a default config if none exists.
    if [ ! -f %{_sysconfdir}/openpropanel/config.json ]; then
        printf '{\n  "listen_addr": ":2087",\n  "acme_email": ""\n}\n' \
            > %{_sysconfdir}/openpropanel/config.json
        chmod 600 %{_sysconfdir}/openpropanel/config.json
    fi
    echo "Open ProPanel installed. Start it with:  systemctl enable --now openpropanel"
    echo "Then read the first-run admin password from: journalctl -u openpropanel"
fi

%preun
%systemd_preun openpropanel.service

%postun
%systemd_postun_with_restart openpropanel.service

%changelog
* Mon Jul 07 2026 Open ProPanel <noreply@example.com> - 0.1.0-1
- Initial package: dashboard, domains, subdomains, per-site PHP-FPM, auto SSL.
