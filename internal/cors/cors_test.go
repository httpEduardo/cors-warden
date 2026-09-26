package cors

import (
	"strings"
	"testing"
)

func trust(t *testing.T, entries ...string) *TrustList {
	t.Helper()
	tl, err := NewTrustList(entries)
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

func TestTrustList(t *testing.T) {
	tl := trust(t, "example.com", "https://partner.io")
	cases := map[string]bool{
		"https://example.com":              true,
		"https://app.example.com":          true,
		"https://APP.example.com:443":      true,
		"http://app.example.com":           false, // domains only trust HTTPS
		"https://evilexample.com":          false,
		"https://example.com.attacker.net": false,
		"https://partner.io":               true,
		"https://sub.partner.io":           false, // full origins are exact
		"null":                             false,
	}
	for origin, want := range cases {
		if got := tl.Trusted(origin); got != want {
			t.Errorf("Trusted(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestInvalidTrustEntries(t *testing.T) {
	for _, e := range []string{"*.example.com", "example.com/path", "ftp://x"} {
		if _, err := NewTrustList([]string{e}); err == nil {
			t.Errorf("expected error for %q", e)
		}
	}
}

func TestParse(t *testing.T) {
	obs, errs, err := Parse(strings.NewReader("# comment\n\na|b|true|/x\nbad\nc|d|maybe\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Endpoint != "/x" || !obs[0].Credentials || obs[0].Line != 3 {
		t.Fatalf("unexpected observations: %+v", obs)
	}
	if len(errs) != 2 || errs[0].Line != 4 || errs[1].Line != 5 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
}

func analyze(t *testing.T, line string, tl *TrustList) []Finding {
	t.Helper()
	obs, errs, _ := Parse(strings.NewReader(line))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	return Analyze(obs, tl)
}

func TestRules(t *testing.T) {
	tl := trust(t, "example.com")
	tests := []struct {
		line string
		rule string
		sev  Severity
	}{
		{"https://evil.test|https://evil.test|true", "CORS001", Critical},
		{"https://evil.test|https://evil.test|false", "CORS001", High},
		{"https://app.example.com|https://evil.test|false", "CORS002", Medium},
		{"null|null|true", "CORS003", Critical},
		{"null|null|false", "CORS003", High},
		{"https://x.test|*|true", "CORS004", Medium},
		{"https://x.test|*|false", "CORS005", Info},
		{"http://app.example.com|http://app.example.com|true", "CORS006", High},
		{"https://a.test|not an origin|false", "CORS008", Low},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			var hit *Finding
			findings := analyze(t, tt.line, tl)
			for i := range findings {
				if findings[i].RuleID == tt.rule {
					hit = &findings[i]
				}
			}
			if hit == nil || hit.Severity != tt.sev {
				t.Fatalf("want %s/%v, got %+v", tt.rule, tt.sev, findings)
			}
		})
	}
}

func TestTrustedOriginIsClean(t *testing.T) {
	if f := analyze(t, "https://app.example.com|https://app.example.com|true", trust(t, "example.com")); len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}

func TestLookalikeIsExplained(t *testing.T) {
	f := analyze(t, "https://example.com.attacker.net|https://example.com.attacker.net|true", trust(t, "example.com"))
	if len(f) != 1 || !strings.Contains(f[0].Message, "suffix match") {
		t.Fatalf("expected a lookalike hint, got %+v", f)
	}
}

func TestWithoutTrustList(t *testing.T) {
	f := analyze(t, "https://evil.test|https://evil.test|true", trust(t))
	if len(f) != 1 || f[0].RuleID != "CORS000" {
		t.Fatalf("expected CORS000, got %+v", f)
	}
}

func TestPlainHTTPSubdomainIsNotALookalike(t *testing.T) {
	f := analyze(t, "http://intranet.example.com|http://intranet.example.com|true", trust(t, "example.com"))
	if len(f) != 2 || !strings.Contains(f[0].Message, "only over HTTPS") || strings.Contains(f[0].Message, "suffix") {
		t.Fatalf("unexpected findings: %+v", f)
	}
}
