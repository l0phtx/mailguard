package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/l0phtx/mailguard/internal/resolver"
)

// RFC 7208 section 4.6.4: evaluating SPF may cause at most 10 DNS lookups.
const maxSPFLookups = 10

var spfMechanisms = map[string]bool{
	"all": true, "include": true, "a": true, "mx": true,
	"ptr": true, "ip4": true, "ip6": true, "exists": true,
}

// Mechanisms and modifiers that cost one DNS lookup each.
var spfLookupTerms = map[string]bool{
	"include": true, "a": true, "mx": true, "ptr": true, "exists": true, "redirect": true,
}

// CheckSPF fetches and evaluates the SPF record of domain, following include
// and redirect chains to count DNS lookups.
func CheckSPF(ctx context.Context, r resolver.Resolver, domain string) SPFResult {
	record, err := findSPF(ctx, r, domain)
	if err != nil {
		return SPFResult{Status: statusFor(err), Issues: []string{err.Error()}}
	}
	if record == "" {
		return SPFResult{
			Status: StatusMissing,
			Issues: []string{`no SPF record; anyone can send mail as this domain (publish "v=spf1 ... -all")`},
		}
	}

	res := SPFResult{Record: record}
	w := &spfWalker{ctx: ctx, r: r, visited: map[string]bool{domain: true}}
	all, err := w.walk(domain, record, 0)
	res.Lookups = w.lookups
	res.All = all
	res.Issues = w.issues
	if err != nil {
		res.Status = statusFor(err)
		res.Issues = append(res.Issues, err.Error())
		return res
	}

	switch {
	case res.Lookups > maxSPFLookups:
		res.Status = StatusFail
		res.Issues = append(res.Issues, fmt.Sprintf(
			"%d DNS lookups exceeds the limit of %d; receivers will treat SPF as a permanent error",
			res.Lookups, maxSPFLookups))
	case all == "-all":
		res.Status = StatusPass
	case all == "~all":
		res.Status = StatusPass
		res.Issues = append(res.Issues, `"~all" (softfail) marks spoofed mail as suspicious; "-all" rejects it`)
	case all == "+all":
		res.Status = StatusFail
		res.Issues = append(res.Issues, `"+all" authorizes every server on the internet to send as this domain`)
	case all == "?all":
		res.Status = StatusWeak
		res.Issues = append(res.Issues, `"?all" (neutral) gives no protection against spoofing`)
	default:
		res.Status = StatusWeak
		res.Issues = append(res.Issues, `record has no "all" mechanism, so unlisted senders get a neutral result`)
	}
	return res
}

// findSPF returns the single SPF record for domain, "" if there is none, or an
// error if the lookup failed or the domain publishes more than one.
func findSPF(ctx context.Context, r resolver.Resolver, domain string) (string, error) {
	txts, err := resolver.TXT(ctx, r, domain)
	if err != nil {
		return "", fmt.Errorf("TXT lookup for %s failed: %w", domain, err)
	}
	var found []string
	for _, txt := range txts {
		if isSPF(txt) {
			found = append(found, strings.TrimSpace(txt))
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		return "", permErrorf("%s publishes %d SPF records; exactly one is allowed (permerror)", domain, len(found))
	}
}

func isSPF(txt string) bool {
	txt = strings.ToLower(strings.TrimSpace(txt))
	return txt == "v=spf1" || strings.HasPrefix(txt, "v=spf1 ")
}

type spfWalker struct {
	ctx context.Context
	r   resolver.Resolver
	// visited holds the domains on the current include path, so a loop is
	// caught but two includes of the same domain on different branches are not.
	visited map[string]bool
	lookups int
	issues  []string
}

// walk counts lookups in record and returns the qualifier of its "all"
// mechanism (inherited through redirect=).
func (w *spfWalker) walk(domain, record string, depth int) (string, error) {
	if depth > maxSPFLookups {
		return "", permErrorf("include chain is deeper than %d levels", maxSPFLookups)
	}
	var all, redirect string
	var includes []string

	for _, term := range strings.Fields(record)[1:] {
		name, value, isModifier := splitSPFTerm(term)
		lowerName := strings.ToLower(name)
		if isModifier {
			switch lowerName {
			case "redirect":
				w.lookups++
				redirect = value
			case "exp":
			default:
				// Unknown modifiers must be ignored (RFC 7208 section 6).
			}
			continue
		}

		qualifier := "+"
		if strings.ContainsAny(lowerName[:1], "+-~?") {
			qualifier, lowerName = lowerName[:1], lowerName[1:]
		}
		if !spfMechanisms[lowerName] {
			return "", permErrorf("invalid SPF term %q in %s", term, domain)
		}
		if spfLookupTerms[lowerName] {
			w.lookups++
		}
		switch lowerName {
		case "all":
			all = qualifier + "all"
		case "include":
			if value == "" {
				return "", permErrorf("include without a domain in %s", domain)
			}
			includes = append(includes, value)
		case "ptr":
			if depth == 0 {
				w.issues = append(w.issues, `"ptr" is deprecated (RFC 7208) and slow; replace it with ip4/ip6 ranges`)
			}
		}
	}

	for _, target := range includes {
		if err := w.follow(domain, target, depth, "include"); err != nil {
			return "", err
		}
	}
	// redirect= only applies when the record has no "all" mechanism.
	if redirect != "" && all == "" {
		target := strings.ToLower(redirect)
		if w.visited[target] {
			return "", permErrorf("redirect loop at %s", target)
		}
		w.visited[target] = true
		defer delete(w.visited, target)
		rec, err := findSPF(w.ctx, w.r, target)
		if err != nil {
			return "", err
		}
		if rec == "" {
			return "", permErrorf("redirect target %s has no SPF record (permerror)", target)
		}
		return w.walk(target, rec, depth+1)
	}
	return all, nil
}

func (w *spfWalker) follow(parent, target string, depth int, kind string) error {
	target = strings.ToLower(target)
	if strings.Contains(target, "%{") {
		// Macro expansion depends on the sender; it cannot be followed statically.
		w.issues = append(w.issues, fmt.Sprintf("%s:%s uses SPF macros; lookups inside it were not counted", kind, target))
		return nil
	}
	if w.visited[target] {
		return permErrorf("%s loop: %s includes %s again", kind, parent, target)
	}
	w.visited[target] = true
	defer delete(w.visited, target)
	rec, err := findSPF(w.ctx, w.r, target)
	if err != nil {
		return err
	}
	if rec == "" {
		return permErrorf("%s:%s has no SPF record (permerror)", kind, target)
	}
	_, err = w.walk(target, rec, depth+1)
	return err
}

// splitSPFTerm splits "include:example.com" into name and value. Modifiers use
// "=" (redirect=example.com); mechanisms use ":" or "/" (ip4:1.2.3.4, a/24).
func splitSPFTerm(term string) (name, value string, isModifier bool) {
	eq := strings.IndexByte(term, '=')
	colon := strings.IndexAny(term, ":/")
	if eq > 0 && (colon < 0 || eq < colon) {
		return term[:eq], term[eq+1:], true
	}
	if colon >= 0 {
		v := term[colon:]
		if v[0] == ':' {
			v = v[1:]
		}
		return term[:colon], v, false
	}
	return term, "", false
}
