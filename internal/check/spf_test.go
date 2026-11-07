package check

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/l0phtx/mailguard/internal/resolver"
)

func TestCheckSPF(t *testing.T) {
	tests := []struct {
		name    string
		txt     map[string][]string
		status  Status
		all     string
		lookups int
		issue   string
	}{
		{
			name:   "hard fail",
			txt:    map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}},
			status: StatusPass, all: "-all",
		},
		{
			name:   "soft fail is a pass with a note",
			txt:    map[string][]string{"example.com": {"v=spf1 mx ~all"}},
			status: StatusPass, all: "~all", lookups: 1, issue: "softfail",
		},
		{
			name:   "neutral",
			txt:    map[string][]string{"example.com": {"v=spf1 a ?all"}},
			status: StatusWeak, all: "?all", lookups: 1,
		},
		{
			name:   "plus all",
			txt:    map[string][]string{"example.com": {"v=spf1 +all"}},
			status: StatusFail, all: "+all", issue: "every server",
		},
		{
			name:   "no all mechanism",
			txt:    map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.1"}},
			status: StatusWeak, issue: `no "all"`,
		},
		{
			name:   "missing",
			txt:    map[string][]string{"example.com": {"google-site-verification=abc"}},
			status: StatusMissing,
		},
		{
			name:   "two records",
			txt:    map[string][]string{"example.com": {"v=spf1 -all", "v=spf1 ~all"}},
			status: StatusFail, issue: "2 SPF records",
		},
		{
			name: "includes are followed and counted",
			txt: map[string][]string{
				"example.com":           {"v=spf1 include:_spf.google.com include:mail.zendesk.com -all"},
				"_spf.google.com":       {"v=spf1 include:_netblocks.google.com ~all"},
				"_netblocks.google.com": {"v=spf1 ip4:35.190.247.0/24 ~all"},
				"mail.zendesk.com":      {"v=spf1 a mx -all"},
			},
			status: StatusPass, all: "-all", lookups: 5,
		},
		{
			name: "same include on two branches is not a loop",
			txt: map[string][]string{
				"example.com":    {"v=spf1 include:a.example include:b.example -all"},
				"a.example":      {"v=spf1 include:shared.example -all"},
				"b.example":      {"v=spf1 include:shared.example -all"},
				"shared.example": {"v=spf1 ip4:192.0.2.1 -all"},
			},
			status: StatusPass, all: "-all", lookups: 4,
		},
		{
			name: "too many lookups",
			txt: map[string][]string{
				"example.com": {"v=spf1 include:a.example include:b.example -all"},
				"a.example":   {"v=spf1 a mx a:x.example mx:y.example exists:z.example -all"},
				"b.example":   {"v=spf1 a mx a:x.example mx:y.example -all"},
			},
			status: StatusFail, lookups: 11, issue: "exceeds the limit of 10",
		},
		{
			name: "include loop",
			txt: map[string][]string{
				"example.com": {"v=spf1 include:a.example -all"},
				"a.example":   {"v=spf1 include:example.com -all"},
			},
			status: StatusFail, issue: "loop",
		},
		{
			name: "include without SPF record",
			txt: map[string][]string{
				"example.com": {"v=spf1 include:gone.example -all"},
			},
			status: StatusFail, issue: "gone.example has no SPF record",
		},
		{
			name: "redirect inherits all",
			txt: map[string][]string{
				"example.com":      {"v=spf1 redirect=_spf.example.com"},
				"_spf.example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
			},
			status: StatusPass, all: "-all", lookups: 1,
		},
		{
			name:   "invalid mechanism",
			txt:    map[string][]string{"example.com": {"v=spf1 ipv4:192.0.2.1 -all"}},
			status: StatusFail, issue: "invalid SPF term",
		},
		{
			name:   "ptr is deprecated",
			txt:    map[string][]string{"example.com": {"v=spf1 ptr -all"}},
			status: StatusPass, all: "-all", lookups: 1, issue: "deprecated",
		},
		{
			name:   "macros are not followed",
			txt:    map[string][]string{"example.com": {"v=spf1 include:%{d}.spf.example -all"}},
			status: StatusPass, all: "-all", lookups: 1, issue: "macros",
		},
		{
			name:   "case insensitive",
			txt:    map[string][]string{"example.com": {"V=SPF1 IP4:192.0.2.1 -ALL"}},
			status: StatusPass, all: "-all",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &resolver.Fake{TXTRecords: tt.txt}
			got := CheckSPF(context.Background(), r, "example.com")
			if got.Status != tt.status {
				t.Fatalf("status = %s, want %s (issues: %v)", got.Status, tt.status, got.Issues)
			}
			if tt.all != "" && got.All != tt.all {
				t.Errorf("all = %q, want %q", got.All, tt.all)
			}
			if tt.lookups != 0 && got.Lookups != tt.lookups {
				t.Errorf("lookups = %d, want %d", got.Lookups, tt.lookups)
			}
			if tt.issue != "" && !hasIssue(got.Issues, tt.issue) {
				t.Errorf("issues %v do not mention %q", got.Issues, tt.issue)
			}
		})
	}
}

func TestCheckSPFDNSError(t *testing.T) {
	r := &resolver.Fake{Errors: map[string]error{"example.com": errors.New("i/o timeout")}}
	got := CheckSPF(context.Background(), r, "example.com")
	if got.Status != StatusError {
		t.Fatalf("status = %s, want error", got.Status)
	}
}

func TestSplitSPFTerm(t *testing.T) {
	tests := []struct {
		term, name, value string
		modifier          bool
	}{
		{"include:_spf.google.com", "include", "_spf.google.com", false},
		{"redirect=_spf.example.com", "redirect", "_spf.example.com", true},
		{"a/24", "a", "/24", false},
		{"mx", "mx", "", false},
		{"-all", "-all", "", false},
		{"exists:%{i}.example.com", "exists", "%{i}.example.com", false},
	}
	for _, tt := range tests {
		name, value, mod := splitSPFTerm(tt.term)
		if name != tt.name || value != tt.value || mod != tt.modifier {
			t.Errorf("splitSPFTerm(%q) = %q, %q, %v", tt.term, name, value, mod)
		}
	}
}

func hasIssue(issues []string, substr string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, substr) {
			return true
		}
	}
	return false
}
