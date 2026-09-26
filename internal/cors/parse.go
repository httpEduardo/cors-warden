// Package cors evaluates observed CORS responses against a list of
// trusted origins.
package cors

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// Observation is one request/response pair: the Origin header that was
// sent and the Access-Control-* headers that came back.
type Observation struct {
	Line        int
	Origin      string // Origin request header
	AllowOrigin string // Access-Control-Allow-Origin response header
	Credentials bool   // Access-Control-Allow-Credentials: true
	Endpoint    string // optional URL, for context
}

// ParseError describes a malformed input line.
type ParseError struct {
	Line   int
	Reason string
}

func (e ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Reason) }

// Parse reads observations in the format
//
//	origin|allow_origin|allow_credentials[|endpoint]
//
// Blank lines and lines starting with '#' are ignored.
func Parse(r io.Reader) ([]Observation, []ParseError, error) {
	var obs []Observation
	var errs []ParseError

	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 || len(parts) > 4 {
			errs = append(errs, ParseError{n, fmt.Sprintf("expected 3 or 4 '|'-separated fields, got %d", len(parts))})
			continue
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		var creds bool
		switch strings.ToLower(parts[2]) {
		case "true":
			creds = true
		case "false":
			creds = false
		default:
			errs = append(errs, ParseError{n, fmt.Sprintf("allow_credentials must be true or false, got %q", parts[2])})
			continue
		}

		o := Observation{Line: n, Origin: parts[0], AllowOrigin: parts[1], Credentials: creds}
		if len(parts) == 4 {
			o.Endpoint = parts[3]
		}
		obs = append(obs, o)
	}
	return obs, errs, sc.Err()
}

// TrustList decides whether an origin is trusted. Entries are either full
// origins ("https://app.example.com") or bare domains ("example.com"),
// which also cover subdomains over HTTPS.
type TrustList struct {
	origins map[string]bool
	domains []string
}

// NewTrustList builds a trust list from raw entries.
func NewTrustList(entries []string) (*TrustList, error) {
	t := &TrustList{origins: map[string]bool{}}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if strings.Contains(e, "://") {
			norm, ok := normalizeOrigin(e)
			if !ok {
				return nil, fmt.Errorf("invalid trusted origin %q", e)
			}
			t.origins[norm] = true
			continue
		}
		if strings.ContainsAny(e, "/:*") {
			return nil, fmt.Errorf("invalid trusted domain %q (use a bare domain like example.com)", e)
		}
		t.domains = append(t.domains, strings.TrimPrefix(e, "."))
	}
	sort.Strings(t.domains)
	return t, nil
}

// Empty reports whether no trusted origins were configured.
func (t *TrustList) Empty() bool { return len(t.origins) == 0 && len(t.domains) == 0 }

// Trusted reports whether origin is on the list.
func (t *TrustList) Trusted(origin string) bool {
	norm, ok := normalizeOrigin(origin)
	if !ok {
		return false
	}
	if t.origins[norm] {
		return true
	}
	u, _ := url.Parse(norm)
	if u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	for _, d := range t.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// resemblesTrusted reports whether an untrusted origin contains a trusted
// domain, which usually means the server matches origins with a naive
// prefix/suffix/substring check (e.g. "evilexample.com" or
// "example.com.attacker.net").
func (t *TrustList) resemblesTrusted(origin string) string {
	norm, ok := normalizeOrigin(origin)
	if !ok {
		return ""
	}
	u, _ := url.Parse(norm)
	host := u.Hostname()
	for _, d := range t.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return "" // a real subdomain, not a lookalike
		}
	}
	for _, d := range t.domains {
		if strings.Contains(host, d) {
			return d
		}
	}
	for o := range t.origins {
		ou, _ := url.Parse(o)
		if h := ou.Hostname(); h != host && strings.Contains(host, h) {
			return h
		}
	}
	return ""
}

// trustedOverHTTPS reports whether origin would be trusted if it used HTTPS.
func (t *TrustList) trustedOverHTTPS(origin string) bool {
	norm, ok := normalizeOrigin(origin)
	if !ok || !strings.HasPrefix(norm, "http://") {
		return false
	}
	return t.Trusted("https://" + strings.TrimPrefix(norm, "http://"))
}

func normalizeOrigin(s string) (string, bool) {
	u, err := url.Parse(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	// Origin values contain only scheme, host, and optional port; paths,
	// credentials, queries, and fragments are not part of an origin.
	if u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.Contains(s, "#") {
		return "", false
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	host := u.Hostname()
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, true
}

func isLocal(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
