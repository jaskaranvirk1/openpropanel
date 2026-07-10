package vhostscan

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression for the adopt-with-custom-cert bug: a site using its own (non
// Let's Encrypt) certificate must have those exact cert/key paths captured, so
// adoption re-emits them instead of forcing a missing LE path.
func TestApacheCapturesCustomCert(t *testing.T) {
	dir := t.TempDir()
	conf := `<VirtualHost *:80>
    ServerName tp.bvdpetro.com
    DocumentRoot /var/www/html/bvdalerts/frontend/dist/frontend/browser/
    RewriteEngine on
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<VirtualHost *:443>
    ServerName tp.bvdpetro.com
    DocumentRoot /var/www/html/bvdalerts/frontend/dist/frontend/browser/
    SSLEngine On
    SSLCertificateFile /etc/ssl/bvdpetro/bvdpetro.crt
    SSLCertificateKeyFile /etc/ssl/bvdpetro/bvdpetro.key
</VirtualHost>
`
	if err := os.WriteFile(filepath.Join(dir, "tp.bvdpetro.com.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	sites, err := Apache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(sites))
	}
	s := sites[0]
	if s.Domain != "tp.bvdpetro.com" {
		t.Errorf("domain = %q", s.Domain)
	}
	if !s.SSL {
		t.Error("SSL should be detected")
	}
	if s.CertFile != "/etc/ssl/bvdpetro/bvdpetro.crt" {
		t.Errorf("CertFile = %q, want the custom cert path", s.CertFile)
	}
	if s.KeyFile != "/etc/ssl/bvdpetro/bvdpetro.key" {
		t.Errorf("KeyFile = %q, want the custom key path", s.KeyFile)
	}
}

// certbot's Apache plugin splits a site into <domain>.conf (no cert) and
// <domain>-le-ssl.conf (the cert). The merged result must carry the cert paths.
func TestApacheMergesSplitCertbotCert(t *testing.T) {
	dir := t.TempDir()
	base := `<VirtualHost *:80>
    ServerName shop.example.com
    DocumentRoot /var/www/shop
</VirtualHost>
`
	le := `<VirtualHost *:443>
    ServerName shop.example.com
    DocumentRoot /var/www/shop
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/shop.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/shop.example.com/privkey.pem
</VirtualHost>
`
	_ = os.WriteFile(filepath.Join(dir, "shop.example.com.conf"), []byte(base), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "shop.example.com-le-ssl.conf"), []byte(le), 0o644)

	sites, err := Apache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("want 1 merged site, got %d", len(sites))
	}
	s := sites[0]
	if !s.SSL || s.CertFile != "/etc/letsencrypt/live/shop.example.com/fullchain.pem" {
		t.Errorf("merged cert not captured: SSL=%v CertFile=%q", s.SSL, s.CertFile)
	}
}

// Nginx: ssl_certificate must be captured without ssl_certificate_key bleeding
// into it (and vice-versa).
func TestNginxCapturesCertPaths(t *testing.T) {
	dir := t.TempDir()
	conf := `server {
    listen 443 ssl;
    server_name api.example.com;
    root /var/www/api;
    ssl_certificate /etc/ssl/api/api.crt;
    ssl_certificate_key /etc/ssl/api/api.key;
}
`
	if err := os.WriteFile(filepath.Join(dir, "api.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	sites, err := Nginx(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(sites))
	}
	s := sites[0]
	if s.CertFile != "/etc/ssl/api/api.crt" {
		t.Errorf("CertFile = %q", s.CertFile)
	}
	if s.KeyFile != "/etc/ssl/api/api.key" {
		t.Errorf("KeyFile = %q", s.KeyFile)
	}
}
