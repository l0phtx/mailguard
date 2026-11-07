package check

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/l0phtx/mailguard/internal/resolver"
)

func TestNormalizeDomain(t *testing.T) {
	valid := map[string]string{
		"example.com":                  "example.com",
		"  Example.COM. ":              "example.com",
		"alice@mail.example.org":       "mail.example.org",
		"https://www.example.com/path": "www.example.com",
		"example.com:443":              "example.com",
		"xn--bcher-kva.example":        "xn--bcher-kva.example",
	}
	for in, want := range valid {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "-bad.com", "exa mple.com", "a..b", "bad-.com", "ex!ample.com"} {
		if _, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted an invalid domain", in)
		}
	}
}

func TestCheckMX(t *testing.T) {
	r := &resolver.Fake{MXRecords: map[string][]*net.MX{
		"example.com": {{Host: "mx2.example.com.", Pref: 20}, {Host: "mx1.example.com.", Pref: 10}},
		"parked.com":  {{Host: ".", Pref: 0}},
	}, Errors: map[string]error{"mx:broken.com": errors.New("server misbehaving")}}

	got := CheckMX(context.Background(), r, "example.com")
	if len(got.Hosts) != 2 || got.Hosts[0] != "mx1.example.com" {
		t.Errorf("hosts = %v, want sorted by preference", got.Hosts)
	}
	if got := CheckMX(context.Background(), r, "parked.com"); !got.NullMX {
		t.Error("null MX not detected")
	}
	if got := CheckMX(context.Background(), r, "nomx.com"); !hasIssue(got.Issues, "no MX records") {
		t.Errorf("issues = %v", got.Issues)
	}
	if got := CheckMX(context.Background(), r, "broken.com"); !hasIssue(got.Issues, "MX lookup failed") {
		t.Errorf("issues = %v", got.Issues)
	}
}

func TestCheckerGradesDomains(t *testing.T) {
	strong := rsaKey(t, 2048)
	r := &resolver.Fake{
		TXTRecords: map[string][]string{
			"secure.com":                      {"v=spf1 include:_spf.secure.com -all"},
			"_spf.secure.com":                 {"v=spf1 ip4:192.0.2.0/24 -all"},
			"_dmarc.secure.com":               {"v=DMARC1; p=reject; rua=mailto:d@secure.com"},
			"selector1._domainkey.secure.com": {"v=DKIM1; k=rsa; p=" + strong},

			"weak.com":        {"v=spf1 mx ~all"},
			"_dmarc.weak.com": {"v=DMARC1; p=none"},

			"parked.com":        {"v=spf1 -all"},
			"_dmarc.parked.com": {"v=DMARC1; p=reject; rua=mailto:d@parked.com"},
		},
		MXRecords: map[string][]*net.MX{
			"secure.com": {{Host: "mx.secure.com.", Pref: 10}},
			"weak.com":   {{Host: "mx.weak.com.", Pref: 10}},
			"open.com":   {{Host: "mx.open.com.", Pref: 10}},
		},
	}
	c := &Checker{Resolver: r, Selectors: DefaultSelectors}
	tests := []struct {
		domain string
		score  int
		grade  string
	}{
		{"secure.com", 100, "A"},
		{"weak.com", 35, "F"},
		{"parked.com", 100, "A"},
		{"open.com", 0, "F"},
	}
	for _, tt := range tests {
		got := c.Check(context.Background(), tt.domain)
		if got.Score != tt.score || got.Grade != tt.grade {
			t.Errorf("%s: got %d %s, want %d %s (issues %v)", tt.domain, got.Score, got.Grade, tt.score, tt.grade, got.Issues())
		}
	}
}

func TestGradeHelpers(t *testing.T) {
	cases := []struct {
		grade, min string
		want       bool
	}{
		{"A", "B", true}, {"B", "B", true}, {"C", "B", false}, {"F", "f", true}, {"?", "A", false},
	}
	for _, c := range cases {
		if got := GradeAtLeast(c.grade, c.min); got != c.want {
			t.Errorf("GradeAtLeast(%q, %q) = %v", c.grade, c.min, got)
		}
	}
	if ValidGrade("E") || !ValidGrade("b") || ValidGrade("AB") {
		t.Error("ValidGrade is wrong")
	}
	for score, want := range map[int]string{100: "A", 90: "A", 89: "B", 75: "B", 60: "C", 40: "D", 39: "F"} {
		if got := letter(score); got != want {
			t.Errorf("letter(%d) = %s, want %s", score, got, want)
		}
	}
}
