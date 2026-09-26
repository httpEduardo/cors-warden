package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const example = "../../examples/responses.txt"

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		want  int
	}{
		{"example with trust list", []string{"-input", example, "-trusted", "example.com"}, "", exitFindings},
		{"clean stdin", []string{"-input", "-", "-trusted", "example.com"}, "https://a.example.com|https://a.example.com|true\n", exitOK},
		{"bad trusted entry", []string{"-input", example, "-trusted", "*.example.com"}, "", exitUsage},
		{"missing file", []string{"-input", "nope.txt"}, "", exitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tt.args, strings.NewReader(tt.stdin), &out, &errOut); got != tt.want {
				t.Fatalf("exit %d, want %d; stderr: %s", got, tt.want, errOut.String())
			}
		})
	}
}

func TestJSONOutput(t *testing.T) {
	var out, errOut bytes.Buffer
	run([]string{"-input", example, "-trusted", "example.com", "-format", "json"}, nil, &out, &errOut)
	var got struct {
		Observations int `json:"observations"`
		Findings     []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Observations != 9 || got.Findings[0].Severity != "critical" {
		t.Fatalf("unexpected report: %+v", got)
	}
}
