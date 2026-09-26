// Command cors-warden reviews observed CORS responses and flags
// configurations that let untrusted sites read protected data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/httpEduardo/cors-warden/internal/cors"
)

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

var version = "dev"

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cors-warden", flag.ContinueOnError)
	fs.SetOutput(stderr)

	input := fs.String("input", "responses.txt", `observations file, or "-" for stdin`)
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "high", "exit with code 1 when a finding reaches this severity")
	showVersion := fs.Bool("version", false, "print the version and exit")
	var trusted listFlag
	fs.Var(&trusted, "trusted", "trusted origin or domain; repeatable or comma-separated (e.g. example.com,https://partner.io)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return exitOK
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "error: unknown format %q\n", *format)
		return exitUsage
	}
	threshold, err := cors.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	trust, err := cors.NewTrustList(trusted)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	var r io.Reader = stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitUsage
		}
		defer f.Close()
		r = f
	}

	obs, parseErrs, err := cors.Parse(r)
	if err != nil {
		fmt.Fprintln(stderr, "error: reading input:", err)
		return exitUsage
	}
	for _, e := range parseErrs {
		fmt.Fprintln(stderr, "warning: skipped", e)
	}
	if trust.Empty() {
		fmt.Fprintln(stderr, "warning: no -trusted origins given; reflected origins cannot be classified as trusted or not")
	}

	findings := cors.Analyze(obs, trust)

	if *format == "json" {
		if findings == nil {
			findings = []cors.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"observations": len(obs), "findings": findings})
	} else {
		writeText(stdout, len(obs), findings)
	}

	if len(findings) > 0 && cors.Worst(findings) >= threshold {
		return exitFindings
	}
	return exitOK
}

func writeText(w io.Writer, total int, findings []cors.Finding) {
	fmt.Fprintf(w, "Reviewed %d CORS responses\n\n", total)
	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}
	counts := map[cors.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
		where := fmt.Sprintf("line %d", f.Line)
		if f.Endpoint != "" {
			where += ", " + f.Endpoint
		}
		fmt.Fprintf(w, "  [%s] %-8s %s\n", f.RuleID, strings.ToUpper(f.Severity.String()), f.Message)
		fmt.Fprintf(w, "  %s            Origin: %s -> Allow-Origin: %s (%s)\n\n", strings.Repeat(" ", len(f.RuleID)), f.Origin, f.AllowOrigin, where)
	}
	var parts []string
	for s := cors.Critical; s >= cors.Info; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	fmt.Fprintf(w, "Summary: %s\n", strings.Join(parts, ", "))
}
