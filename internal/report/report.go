// Package report renders check results as a table, JSON or CSV.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/l0phtx/mailguard/internal/check"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "csv"}

// Write renders reports to w in the given format.
func Write(w io.Writer, format string, reports []check.Report, showIssues bool) error {
	switch format {
	case "table":
		return Table(w, reports, showIssues)
	case "json":
		return JSON(w, reports)
	case "csv":
		return CSV(w, reports)
	default:
		return fmt.Errorf("unknown format %q (use %s)", format, strings.Join(Formats, ", "))
	}
}

// Table writes an aligned summary table, followed by each domain's issues.
func Table(w io.Writer, reports []check.Report, showIssues bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tGRADE\tSCORE\tSPF\tDKIM\tDMARC")
	for _, r := range reports {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n",
			r.Domain, r.Grade, r.Score, spfCell(r.SPF), dkimCell(r.DKIM), dmarcCell(r.DMARC))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if !showIssues {
		return nil
	}
	for _, r := range reports {
		issues := r.Issues()
		if r.Error != "" {
			issues = append([]string{r.Error}, issues...)
		}
		if len(issues) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", r.Domain)
		for _, issue := range issues {
			fmt.Fprintf(w, "  - %s\n", issue)
		}
	}
	return nil
}

func spfCell(s check.SPFResult) string {
	if s.All != "" && (s.Status == check.StatusPass || s.Status == check.StatusWeak) {
		return fmt.Sprintf("%s (%s)", s.Status, s.All)
	}
	return string(s.Status)
}

func dkimCell(d check.DKIMResult) string {
	for _, k := range d.Keys {
		if k.Status != check.StatusMissing {
			n := activeKeys(d)
			return fmt.Sprintf("%s (%d %s)", d.Status, n, plural(n, "key", "keys"))
		}
	}
	return string(d.Status)
}

func dmarcCell(d check.DMARCResult) string {
	if d.Policy == "" {
		return string(d.Status)
	}
	cell := fmt.Sprintf("%s (p=%s", d.Status, d.Policy)
	if d.Percent < 100 {
		cell += fmt.Sprintf(" pct=%d", d.Percent)
	}
	return cell + ")"
}

func activeKeys(d check.DKIMResult) int {
	n := 0
	for _, k := range d.Keys {
		if k.Status != check.StatusMissing {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// JSON writes the full reports as an indented JSON array.
func JSON(w io.Writer, reports []check.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// CSV writes one row per domain, suitable for spreadsheets.
func CSV(w io.Writer, reports []check.Report) error {
	cw := csv.NewWriter(w)
	header := []string{
		"domain", "grade", "score", "spf_status", "spf_all", "spf_lookups", "spf_record",
		"dkim_status", "dkim_selectors", "dmarc_status", "dmarc_policy", "dmarc_pct", "dmarc_record",
		"mx_hosts", "issues",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, r := range reports {
		var selectors []string
		for _, k := range r.DKIM.Keys {
			selectors = append(selectors, k.Selector)
		}
		row := []string{
			r.Domain, r.Grade, strconv.Itoa(r.Score),
			string(r.SPF.Status), r.SPF.All, strconv.Itoa(r.SPF.Lookups), r.SPF.Record,
			string(r.DKIM.Status), strings.Join(selectors, " "),
			string(r.DMARC.Status), r.DMARC.Policy, strconv.Itoa(r.DMARC.Percent), r.DMARC.Record,
			strings.Join(r.MX.Hosts, " "), strings.Join(r.Issues(), " | "),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
