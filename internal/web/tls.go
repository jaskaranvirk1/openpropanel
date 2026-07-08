package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openpropanel/openpropanel/internal/config"
)

// certManager supplies the panel's TLS certificate to crypto/tls via a
// GetCertificate callback. It serves whichever cert is currently on disk:
//   - the operator override (config.TLSCert/TLSKey) when set and present — e.g.
//     a Let's Encrypt cert auto-issued for the panel hostname, or a BYO cert;
//   - otherwise a self-signed certificate it generates under DataDir/tls.
//
// It reloads automatically when the underlying files change (so a certbot
// renewal is picked up on the next TLS handshake — no restart needed).
type certManager struct {
	cfg *config.Config

	mu       sync.Mutex
	cached   *tls.Certificate
	curCert  string
	curKey   string
	modCert  time.Time
	modKey   time.Time
}

func newCertManager(cfg *config.Config) *certManager { return &certManager{cfg: cfg} }

// resolvePaths returns the cert/key files to serve right now: the override if
// it is fully present, otherwise the self-signed fallback.
func (cm *certManager) resolvePaths() (cert, key string) {
	oc, ok := cm.cfg.TLSOverride()
	if oc != "" && ok != "" && fileExists(oc) && fileExists(ok) {
		return oc, ok
	}
	return cm.cfg.SelfSignedCertPath(), cm.cfg.SelfSignedKeyPath()
}

// ensureBootstrap makes sure a usable certificate exists before serving. If we
// are falling back to self-signed and it does not exist yet, generate it.
func (cm *certManager) ensureBootstrap() error {
	cert, key := cm.resolvePaths()
	if cert == cm.cfg.SelfSignedCertPath() && !(fileExists(cert) && fileExists(key)) {
		return generateSelfSigned(cert, key)
	}
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (cm *certManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, key := cm.resolvePaths()
	mc, mk := modTime(cert), modTime(key)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.cached != nil && cm.curCert == cert && cm.curKey == key &&
		cm.modCert.Equal(mc) && cm.modKey.Equal(mk) {
		return cm.cached, nil
	}

	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		// Any load failure — a missing/corrupt override cert, or a deleted
		// self-signed one — regenerates the self-signed fallback so the panel is
		// never left unreachable.
		selfCert, selfKey := cm.cfg.SelfSignedCertPath(), cm.cfg.SelfSignedKeyPath()
		if gerr := generateSelfSigned(selfCert, selfKey); gerr != nil {
			return nil, fmt.Errorf("load %s failed (%v) and self-signed regeneration failed: %w", cert, err, gerr)
		}
		cert, key = selfCert, selfKey
		if pair, err = tls.LoadX509KeyPair(cert, key); err != nil {
			return nil, err
		}
	}

	cm.cached = &pair
	cm.curCert, cm.curKey = cert, key
	cm.modCert, cm.modKey = modTime(cert), modTime(key)
	return cm.cached, nil
}

// generateSelfSigned writes a fresh self-signed EC certificate/key pair.
func generateSelfSigned(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Open ProPanel", Organization: []string{"Open ProPanel"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              certHostnames(),
		IPAddresses:           certIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600)
}

// certHostnames / certIPs keep the self-signed SANs minimal (loopback only) so
// the panel never advertises its private/secondary interface addresses or
// hostname to an unauthenticated TLS client. A real certificate for a public
// name is obtained via Settings → Panel HTTPS.
func certHostnames() []string { return []string{"localhost"} }

func certIPs() []net.IP { return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback} }

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("encode %s: %w", blockType, err)
	}
	return nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func modTime(p string) time.Time {
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}
