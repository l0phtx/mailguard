package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/l0phtx/mailguard/internal/resolver"
)

// Checker runs all checks for a domain.
type Checker struct {
	Resolver  resolver.Resolver
	Selectors []string
}

// Check runs the MX, SPF, DKIM and DMARC checks concurrently and grades them.
func (c *Checker) Check(ctx context.Context, domain string) Report {
	rep := Report{Domain: domain}
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); rep.MX = CheckMX(ctx, c.Resolver, domain) }()
	go func() { defer wg.Done(); rep.SPF = CheckSPF(ctx, c.Resolver, domain) }()
	go func() { defer wg.Done(); rep.DKIM = CheckDKIM(ctx, c.Resolver, domain, c.Selectors) }()
	go func() { defer wg.Done(); rep.DMARC = CheckDMARC(ctx, c.Resolver, domain) }()
	wg.Wait()

	// A domain that accepts no mail should not send any either; DKIM keys are
	// then unnecessary, and "v=spf1 -all" with p=reject is the complete setup.
	if rep.MX.NullMX || len(rep.MX.Hosts) == 0 {
		if rep.DKIM.Status == StatusMissing {
			rep.DKIM.Status = StatusPass
			rep.DKIM.Issues = []string{"no DKIM needed for a domain that does not send mail"}
		}
	}
	if rep.SPF.Status == StatusError || rep.DMARC.Status == StatusError {
		rep.Error = "some DNS lookups failed; the grade may be too low"
	}
	rep.Score, rep.Grade = Grade(rep)
	return rep
}

// CheckMX looks up the mail servers for domain.
func CheckMX(ctx context.Context, r resolver.Resolver, domain string) MXResult {
	records, err := r.LookupMX(ctx, domain)
	if err != nil {
		if resolver.IsNotFound(err) {
			return MXResult{Issues: []string{
				`no MX records; if this domain sends no mail, publish "v=spf1 -all" and "p=reject" to stop spoofing`,
			}}
		}
		return MXResult{Issues: []string{fmt.Sprintf("MX lookup failed: %v", err)}}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	var res MXResult
	for _, mx := range records {
		host := strings.TrimSuffix(mx.Host, ".")
		if host == "" {
			res.NullMX = true
			continue
		}
		res.Hosts = append(res.Hosts, host)
	}
	if res.NullMX {
		res.Issues = append(res.Issues, "null MX (RFC 7505): domain declares that it accepts no mail")
	}
	return res
}

// NormalizeDomain turns "User@Example.COM", "https://example.com/path" or
// "example.com." into "example.com", and rejects values that are not domains.
func NormalizeDomain(input string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(input))
	if _, after, ok := strings.Cut(d, "://"); ok {
		d = after
	}
	if i := strings.LastIndexByte(d, '@'); i >= 0 {
		d = d[i+1:]
	}
	if i := strings.IndexAny(d, "/:?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")

	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return "", fmt.Errorf("%q is not a domain name", input)
	}
	for _, label := range strings.Split(d, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("%q is not a domain name", input)
		}
	}
	return d, nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}
