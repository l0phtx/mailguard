package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/l0phtx/mailguard/internal/check"
)

func sample() []check.Report {
	return []check.Report{
		{
			Domain: "secure.com", Grade: "A", Score: 100,
			SPF:   check.SPFResult{Status: check.StatusPass, All: "-all", Record: "v=spf1 -all", Lookups: 1},
			DKIM:  check.DKIMResult{Status: check.StatusPass, Keys: []check.DKIMKey{{Selector: "google", KeyType: "rsa", Bits: 2048, Status: check.StatusPass}}},
			DMARC: check.DMARCResult{Status: check.StatusPass, Policy: "reject", Percent: 100},
		},
		{
			Domain: "weak.com", Grade: "F", Score: 35,
			SPF:   check.SPFResult{Status: check.StatusPass, All: "~all", Issues: []string{"softfail"}},
			DKIM:  check.DKIMResult{Status: check.StatusMissing},
			DMARC: check.DMARCResult{Status: check.StatusWeak, Policy: "none", Percent: 100, Issues: []string{"p=none only monitors"}},
		},
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", sample(), true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"DOMAIN", "pass (-all)", "pass (1 key)", "pass (p=reject)", "weak (p=none)", "  - DMARC: p=none only monitors"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	buf.Reset()
	_ = Write(&buf, "table", sample(), false)
	if strings.Contains(buf.String(), "only monitors") {
		t.Error("quiet table still lists issues")
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", sample(), false); err != nil {
		t.Fatal(err)
	}
	var decoded []check.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].DKIM.Keys[0].Bits != 2048 {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "csv", sample(), false); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[1][0] != "secure.com" || rows[2][1] != "F" {
		t.Errorf("unexpected CSV rows: %v", rows)
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", nil, false); err == nil {
		t.Error("expected an error for an unknown format")
	}
}
