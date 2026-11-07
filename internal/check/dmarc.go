package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/l0phtx/mailguard/internal/resolver"
)

// maxTreeWalk caps how many parent domains are queried for an inherited
// policy, as in the DMARCbis DNS tree walk.
const maxTreeWalk = 8

// CheckDMARC finds the DMARC policy that applies to domain. If the domain has
// no record of its own, MailGuard walks up the DNS tree (DMARCbis) and uses
// the first parent record it finds, applying that record's sp= policy.
func CheckDMARC(ctx context.Context, r resolver.Resolver, domain string) DMARCResult {
	for i, name := range treeWalk(domain) {
		record, err := findDMARC(ctx, r, name)
		if err != nil {
			return DMARCResult{Status: statusFor(err), Issues: []string{err.Error()}}
		}
		if record != "" {
			return evaluateDMARC(record, "_dmarc."+name, i > 0)
		}
	}
	return DMARCResult{
		Status: StatusMissing,
		Issues: []string{`no DMARC record; publish "v=DMARC1; p=none; rua=mailto:..." to start monitoring`},
	}
}

// treeWalk returns domain followed by its parents, stopping before the
// top-level domain: a.b.example.com -> [a.b.example.com b.example.com example.com].
func treeWalk(domain string) []string {
	labels := strings.Split(domain, ".")
	var names []string
	for i := 0; i < len(labels)-1 && len(names) < maxTreeWalk; i++ {
		names = append(names, strings.Join(labels[i:], "."))
	}
	return names
}

func findDMARC(ctx context.Context, r resolver.Resolver, domain string) (string, error) {
	txts, err := resolver.TXT(ctx, r, "_dmarc."+domain)
	if err != nil {
		return "", fmt.Errorf("TXT lookup for _dmarc.%s failed: %w", domain, err)
	}
	var found []string
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			found = append(found, strings.TrimSpace(txt))
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		// Receivers must ignore DMARC entirely when several records exist.
		return "", permErrorf("_dmarc.%s has %d DMARC records; receivers will ignore all of them", domain, len(found))
	}
}

func parseTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return tags
}

func evaluateDMARC(record, source string, inherited bool) DMARCResult {
	res := DMARCResult{Record: record, Source: source, Percent: 100}
	tags := parseTags(record)

	policy := strings.ToLower(tags["p"])
	if !validPolicy(policy) {
		res.Status = StatusFail
		res.Issues = append(res.Issues, fmt.Sprintf("p=%q is not a valid policy; use none, quarantine or reject", tags["p"]))
		return res
	}
	res.SubdomainPolicy = policy
	if sp, ok := tags["sp"]; ok {
		if !validPolicy(strings.ToLower(sp)) {
			res.Issues = append(res.Issues, fmt.Sprintf("sp=%q is not a valid policy and is ignored", sp))
		} else {
			res.SubdomainPolicy = strings.ToLower(sp)
		}
	}
	res.Policy = policy
	if inherited {
		res.Policy = res.SubdomainPolicy
		res.Issues = append(res.Issues, "no record of its own; inherits the policy from "+source)
	}

	if pct, ok := tags["pct"]; ok {
		n, err := strconv.Atoi(pct)
		if err != nil || n < 0 || n > 100 {
			res.Issues = append(res.Issues, fmt.Sprintf("pct=%q is invalid; receivers will use 100", pct))
		} else {
			res.Percent = n
		}
	}
	if rua := tags["rua"]; rua != "" {
		for _, uri := range strings.Split(rua, ",") {
			res.ReportURIs = append(res.ReportURIs, strings.TrimSpace(uri))
		}
	} else {
		res.Issues = append(res.Issues, "no rua= address, so you receive no reports about who sends as your domain")
	}

	switch res.Policy {
	case "reject", "quarantine":
		res.Status = StatusPass
		if res.Percent < 100 {
			res.Status = StatusWeak
			res.Issues = append(res.Issues, fmt.Sprintf("pct=%d applies the policy to only part of failing mail", res.Percent))
		}
		if res.Policy == "quarantine" {
			res.Issues = append(res.Issues, `p=quarantine sends spoofed mail to spam; p=reject blocks it`)
		}
	default:
		res.Status = StatusWeak
		res.Issues = append(res.Issues, "p=none only monitors; spoofed mail is still delivered")
	}
	if !inherited && res.Policy != "none" && res.SubdomainPolicy == "none" {
		res.Issues = append(res.Issues, "sp=none leaves subdomains unprotected")
	}
	return res
}

func validPolicy(p string) bool {
	return p == "none" || p == "quarantine" || p == "reject"
}
