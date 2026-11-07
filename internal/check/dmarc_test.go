package check

import (
	"context"
	"strings"
	"testing"

	"github.com/l0phtx/mailguard/internal/resolver"
)

func TestTreeWalk(t *testing.T) {
	got := strings.Join(treeWalk("a.b.example.co.uk"), " ")
	if got != "a.b.example.co.uk b.example.co.uk example.co.uk co.uk" {
		t.Errorf("treeWalk = %s", got)
	}
	if n := len(treeWalk("a.b.c.d.e.f.g.h.i.j.example.com")); n != maxTreeWalk {
		t.Errorf("treeWalk returned %d names, want %d", n, maxTreeWalk)
	}
}

func TestCheckDMARC(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		txt       map[string][]string
		status    Status
		policy    string
		pct       int
		issue     string
		noIssue   string
		inherited bool
	}{
		{
			name: "reject", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"}},
			status: StatusPass, policy: "reject", pct: 100, noIssue: "rua",
		},
		{
			name: "quarantine", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=quarantine; rua=mailto:d@example.com"}},
			status: StatusPass, policy: "quarantine", pct: 100, issue: "p=reject blocks it",
		},
		{
			name: "monitoring only", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=none"}},
			status: StatusWeak, policy: "none", issue: "no rua=",
		},
		{
			name: "partial pct", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; pct=25; rua=mailto:d@example.com"}},
			status: StatusWeak, policy: "reject", pct: 25, issue: "pct=25",
		},
		{
			name: "invalid policy", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=block"}},
			status: StatusFail,
		},
		{
			name: "missing p tag", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; rua=mailto:d@example.com"}},
			status: StatusFail,
		},
		{
			name: "missing", domain: "example.com",
			txt:    map[string][]string{},
			status: StatusMissing,
		},
		{
			name: "duplicate records", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject", "v=DMARC1; p=none"}},
			status: StatusFail, issue: "will ignore all",
		},
		{
			name: "subdomain inherits sp", domain: "mail.example.co.uk",
			txt:    map[string][]string{"_dmarc.example.co.uk": {"v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.co.uk"}},
			status: StatusPass, policy: "quarantine", inherited: true, issue: "inherits",
		},
		{
			name: "closest parent wins", domain: "a.eu.example.com",
			txt: map[string][]string{
				"_dmarc.eu.example.com": {"v=DMARC1; p=quarantine; sp=none; rua=mailto:d@example.com"},
				"_dmarc.example.com":    {"v=DMARC1; p=reject; rua=mailto:d@example.com"},
			},
			status: StatusWeak, policy: "none", inherited: true,
		},
		{
			name: "subdomain inherits p when no sp", domain: "news.example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"}},
			status: StatusPass, policy: "reject", inherited: true,
		},
		{
			name: "sp=none warning", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"}},
			status: StatusPass, policy: "reject", issue: "subdomains unprotected",
		},
		{
			name: "invalid pct falls back to 100", domain: "example.com",
			txt:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; pct=abc; rua=mailto:d@example.com"}},
			status: StatusPass, policy: "reject", pct: 100, issue: "pct=\"abc\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckDMARC(context.Background(), &resolver.Fake{TXTRecords: tt.txt}, tt.domain)
			if got.Status != tt.status {
				t.Fatalf("status = %s, want %s (issues: %v)", got.Status, tt.status, got.Issues)
			}
			if tt.policy != "" && got.Policy != tt.policy {
				t.Errorf("policy = %q, want %q", got.Policy, tt.policy)
			}
			if tt.pct != 0 && got.Percent != tt.pct {
				t.Errorf("pct = %d, want %d", got.Percent, tt.pct)
			}
			if tt.issue != "" && !hasIssue(got.Issues, tt.issue) {
				t.Errorf("issues %v do not mention %q", got.Issues, tt.issue)
			}
			if tt.noIssue != "" && hasIssue(got.Issues, tt.noIssue) {
				t.Errorf("issues %v should not mention %q", got.Issues, tt.noIssue)
			}
			if tt.inherited && got.Source == "_dmarc."+tt.domain {
				t.Errorf("source = %q, expected the organizational domain", got.Source)
			}
		})
	}
}
