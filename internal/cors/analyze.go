package cors

import (
	"fmt"
	"sort"
	"strings"
)

// Severity ranks findings.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return "unknown"
}

// MarshalText renders severities as strings in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converts a name such as "high".
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(n, strings.TrimSpace(name)) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", name)
}

// Finding is an issue detected in one observation.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Line        int      `json:"line"`
	Origin      string   `json:"origin"`
	AllowOrigin string   `json:"allow_origin"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Message     string   `json:"message"`
}

// Analyze evaluates every observation and returns findings ordered by
// severity, then input order.
func Analyze(obs []Observation, trust *TrustList) []Finding {
	var out []Finding
	for _, o := range obs {
		out = append(out, analyzeOne(o, trust)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func analyzeOne(o Observation, trust *TrustList) []Finding {
	f := func(rule string, sev Severity, msg string, args ...any) Finding {
		return Finding{
			RuleID: rule, Severity: sev, Line: o.Line,
			Origin: o.Origin, AllowOrigin: o.AllowOrigin, Endpoint: o.Endpoint,
			Message: fmt.Sprintf(msg, args...),
		}
	}

	allow := strings.TrimSpace(o.AllowOrigin)
	switch {
	case allow == "":
		return nil // CORS not granted; nothing to report

	case allow == "*":
		if o.Credentials {
			// Browsers refuse this combination, but it shows the server is
			// trying to allow credentialed cross-origin access to anyone.
			return []Finding{f("CORS004", Medium,
				"wildcard origin combined with credentials; browsers reject it, and the usual \"fix\" is to reflect the Origin header, which is worse")}
		}
		return []Finding{f("CORS005", Info, "wildcard origin: any site can read unauthenticated responses")}

	case strings.EqualFold(allow, "null"):
		sev := High
		if o.Credentials {
			sev = Critical
		}
		return []Finding{f("CORS003", sev,
			"allows the \"null\" origin, which any page can obtain from a sandboxed iframe or data: URL")}
	}

	if _, ok := normalizeOrigin(allow); !ok {
		return []Finding{f("CORS008", Low, "Access-Control-Allow-Origin %q is not a valid origin", allow)}
	}

	var out []Finding
	reflected := strings.EqualFold(allow, o.Origin)

	if trust.Empty() {
		if reflected && o.Credentials {
			out = append(out, f("CORS000", Low,
				"origin is echoed back with credentials; pass -trusted to tell whether this origin is expected"))
		}
		return out
	}

	if !trust.Trusted(allow) {
		sev := Medium
		verb := "allows"
		if reflected {
			verb = "reflects"
			sev = High
		}
		if o.Credentials {
			sev = Critical
		}
		msg := fmt.Sprintf("%s untrusted origin %s", verb, allow)
		if o.Credentials {
			msg += " with credentials, so that site can read authenticated responses"
		}
		if trust.trustedOverHTTPS(allow) {
			msg += " (the domain is trusted, but only over HTTPS)"
		} else if lookalike := trust.resemblesTrusted(allow); lookalike != "" {
			msg += fmt.Sprintf(" (it contains %q, which suggests a substring or suffix match in the allowlist check)", lookalike)
		}
		rule := "CORS002"
		if reflected {
			rule = "CORS001"
		}
		out = append(out, f(rule, sev, "%s", msg))
	}

	if strings.HasPrefix(strings.ToLower(allow), "http://") && !isLocal(allow) {
		sev := Medium
		if o.Credentials {
			sev = High
		}
		out = append(out, f("CORS006", sev,
			"allows an origin served over plain HTTP; a network attacker can inject script into it"))
	}
	return out
}

// Worst returns the highest severity present.
func Worst(findings []Finding) Severity {
	w := Severity(-1)
	for _, fd := range findings {
		if fd.Severity > w {
			w = fd.Severity
		}
	}
	return w
}
