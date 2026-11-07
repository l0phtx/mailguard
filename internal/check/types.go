// Package check implements the SPF, DKIM and DMARC checks and the grading.
package check

// Status is the outcome of a single check.
type Status string

const (
	StatusPass    Status = "pass"    // configured and enforcing
	StatusWeak    Status = "weak"    // present but easy to bypass or monitoring only
	StatusMissing Status = "missing" // no record published
	StatusFail    Status = "fail"    // invalid or dangerous configuration
	StatusError   Status = "error"   // DNS lookup failed; result unknown
)

// SPFResult describes a domain's Sender Policy Framework record.
type SPFResult struct {
	Status  Status   `json:"status"`
	Record  string   `json:"record,omitempty"`
	All     string   `json:"all,omitempty"` // qualifier of the final "all": -all, ~all, ?all, +all
	Lookups int      `json:"dns_lookups"`
	Issues  []string `json:"issues,omitempty"`
}

// DMARCResult describes a domain's DMARC policy.
type DMARCResult struct {
	Status          Status   `json:"status"`
	Record          string   `json:"record,omitempty"`
	Source          string   `json:"source,omitempty"` // where the record was found
	Policy          string   `json:"policy,omitempty"` // effective policy for this domain
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Percent         int      `json:"pct"`
	ReportURIs      []string `json:"rua,omitempty"`
	Issues          []string `json:"issues,omitempty"`
}

// DKIMKey is one public key found at a selector.
type DKIMKey struct {
	Selector string `json:"selector"`
	KeyType  string `json:"key_type"`
	Bits     int    `json:"bits,omitempty"`
	Status   Status `json:"status"`
	Note     string `json:"note,omitempty"`
}

// DKIMResult summarizes the DKIM keys found for a domain.
type DKIMResult struct {
	Status Status    `json:"status"`
	Keys   []DKIMKey `json:"keys,omitempty"`
	Issues []string  `json:"issues,omitempty"`
}

// MXResult lists the mail servers for a domain.
type MXResult struct {
	Hosts  []string `json:"hosts,omitempty"`
	NullMX bool     `json:"null_mx,omitempty"` // RFC 7505: domain accepts no mail
	Issues []string `json:"issues,omitempty"`
}

// Report is the full result for one domain.
type Report struct {
	Domain string      `json:"domain"`
	Grade  string      `json:"grade"`
	Score  int         `json:"score"`
	MX     MXResult    `json:"mx"`
	SPF    SPFResult   `json:"spf"`
	DMARC  DMARCResult `json:"dmarc"`
	DKIM   DKIMResult  `json:"dkim"`
	Error  string      `json:"error,omitempty"`
}

// Issues returns every issue in the report, prefixed with the check name.
func (r *Report) Issues() []string {
	var out []string
	add := func(prefix string, issues []string) {
		for _, issue := range issues {
			out = append(out, prefix+": "+issue)
		}
	}
	add("MX", r.MX.Issues)
	add("SPF", r.SPF.Issues)
	add("DKIM", r.DKIM.Issues)
	add("DMARC", r.DMARC.Issues)
	return out
}
