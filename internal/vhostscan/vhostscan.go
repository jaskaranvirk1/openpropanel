// Package vhostscan discovers virtual hosts that already exist on the server
// (configs Open ProPanel did NOT create), so they can be imported into the
// panel and, optionally, adopted for full management. It is a pragmatic,
// best-effort parser: it understands the common shape of Apache <VirtualHost>
// blocks and Nginx server blocks (ServerName/server_name, DocumentRoot/root,
// SSL). Exotic setups (heavy macros, deep includes) may import with partial
// data and can still be adopted manually.
package vhostscan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// managedMarker identifies configs Open ProPanel generated itself.
const managedMarker = "Managed by Open ProPanel"

// Site is a discovered virtual host.
type Site struct {
	Domain  string   // primary ServerName / server_name
	Aliases []string // additional names
	DocRoot string   // DocumentRoot / root ("" if none found)
	SSL     bool     // an HTTPS/SSL block was present
	File    string   // config file it was found in
	Managed bool      // the file carries the Open ProPanel marker
}

var (
	apacheBlockRe = regexp.MustCompile(`(?is)<VirtualHost\b[^>]*>(.*?)</VirtualHost>`)
	serverNameRe  = regexp.MustCompile(`(?im)^[ \t]*ServerName[ \t]+(\S+)`)
	serverAliasRe = regexp.MustCompile(`(?im)^[ \t]*ServerAlias[ \t]+(.+)$`)
	docRootRe     = regexp.MustCompile(`(?im)^[ \t]*DocumentRoot[ \t]+"?([^"\r\n]+?)"?[ \t]*$`)
	apacheSSLRe   = regexp.MustCompile(`(?i)(SSLEngine\s+on|SSLCertificateFile)`)

	ngxNameRe = regexp.MustCompile(`(?im)^[ \t]*server_name[ \t]+([^;{]+);`)
	ngxRootRe = regexp.MustCompile(`(?im)^[ \t]*root[ \t]+([^;{]+);`)
	ngxSSLRe  = regexp.MustCompile(`(?im)^[ \t]*(listen[ \t]+[^;]*\bssl\b|ssl_certificate[ \t])`)

	hostRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+$`)
)

// Apache scans a directory of *.conf files for Apache virtual hosts.
func Apache(dir string) ([]Site, error) { return scan(dir, parseApache) }

// Nginx scans a directory of *.conf files for Nginx server blocks.
func Nginx(dir string) ([]Site, error) { return scan(dir, parseNginx) }

func scan(dir string, parse func(content, file string) []Site) ([]Site, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	merged := map[string]*Site{}
	var order []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		managed := strings.Contains(string(b), managedMarker)
		for _, s := range parse(string(b), path) {
			s.Managed = managed
			if ex, ok := merged[s.Domain]; ok {
				ex.SSL = ex.SSL || s.SSL
				ex.Managed = ex.Managed || s.Managed
				if ex.DocRoot == "" {
					ex.DocRoot = s.DocRoot
				}
				if len(ex.Aliases) == 0 {
					ex.Aliases = s.Aliases
				}
			} else {
				cp := s
				merged[s.Domain] = &cp
				order = append(order, s.Domain)
			}
		}
	}
	out := make([]Site, 0, len(order))
	for _, d := range order {
		out = append(out, *merged[d])
	}
	return out, nil
}

// ParseFile parses a single config file and returns its vhosts, unmerged (one
// entry per block). Used to detect files that define more than one site.
func ParseFile(path string, nginx bool) []Site {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if nginx {
		return parseNginx(string(b), path)
	}
	return parseApache(string(b), path)
}

// FilesForDomain returns the *.conf files in dir that define the given domain.
func FilesForDomain(dir string, nginx bool, domain string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		for _, s := range ParseFile(p, nginx) {
			if s.Domain == domain {
				files = append(files, p)
				break
			}
		}
	}
	return files
}

func parseApache(content, file string) []Site {
	var sites []Site
	for _, m := range apacheBlockRe.FindAllStringSubmatch(content, -1) {
		block := m[1]
		name := firstSubmatch(serverNameRe, block)
		name = strings.ToLower(strings.TrimSuffix(hostOnly(name), "."))
		if !looksLikeDomain(name) {
			continue
		}
		s := Site{Domain: name, File: file, DocRoot: cleanPath(firstSubmatch(docRootRe, block)), SSL: apacheSSLRe.MatchString(block)}
		for _, am := range serverAliasRe.FindAllStringSubmatch(block, -1) {
			for _, a := range strings.Fields(am[1]) {
				if al := strings.ToLower(hostOnly(a)); looksLikeDomain(al) && al != name {
					s.Aliases = append(s.Aliases, al)
				}
			}
		}
		sites = append(sites, s)
	}
	return sites
}

func parseNginx(content, file string) []Site {
	var sites []Site
	for _, block := range braceBlocks(content, "server") {
		names := strings.Fields(firstSubmatch(ngxNameRe, block))
		var domain string
		var aliases []string
		for _, n := range names {
			n = strings.ToLower(strings.Trim(n, "\""))
			if !looksLikeDomain(n) {
				continue
			}
			if domain == "" {
				domain = n
			} else {
				aliases = append(aliases, n)
			}
		}
		if domain == "" {
			continue
		}
		sites = append(sites, Site{
			Domain: domain, Aliases: aliases, File: file,
			DocRoot: cleanPath(firstSubmatch(ngxRootRe, block)),
			SSL:     ngxSSLRe.MatchString(block),
		})
	}
	return sites
}

// braceBlocks returns the inner text of each `<keyword> { ... }` block, matching
// braces so nested blocks are handled.
func braceBlocks(content, keyword string) []string {
	re := regexp.MustCompile(`(?i)(^|\s)` + keyword + `\s*\{`)
	var out []string
	for _, loc := range re.FindAllStringIndex(content, -1) {
		open := loc[1] - 1 // index of '{'
		depth := 0
		for j := open; j < len(content); j++ {
			switch content[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					out = append(out, content[open+1:j])
				}
			}
			if depth == 0 && j > open {
				break
			}
		}
	}
	return out
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func hostOnly(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 { // strip ":port"
		s = s[:i]
	}
	return s
}

func cleanPath(p string) string { return strings.Trim(strings.TrimSpace(p), `"'`) }

func looksLikeDomain(name string) bool {
	if name == "" || name == "_" || strings.ContainsAny(name, "*$ ") {
		return false
	}
	return hostRe.MatchString(name)
}
