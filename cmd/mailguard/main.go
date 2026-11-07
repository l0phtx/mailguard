// Command mailguard grades the email security (SPF, DKIM and DMARC) of a list
// of domains using public DNS.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/l0phtx/mailguard/internal/check"
	"github.com/l0phtx/mailguard/internal/report"
	"github.com/l0phtx/mailguard/internal/resolver"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = ""

const (
	exitOK        = 0
	exitError     = 1
	exitBelowMin  = 2
	maxConcurrent = 500
)

type options struct {
	file        string
	format      string
	concurrency int
	timeout     time.Duration
	server      string
	selectors   string
	failUnder   string
	quiet       bool
	version     bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, domains, err := parseArgs(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, "mailguard:", err)
		return exitError
	}
	if opts.version {
		fmt.Fprintln(stdout, "mailguard", buildVersion())
		return exitOK
	}

	if opts.file != "" {
		fromFile, err := readDomains(opts.file, stdin)
		if err != nil {
			fmt.Fprintln(stderr, "mailguard:", err)
			return exitError
		}
		domains = append(domains, fromFile...)
	}
	domains, err = normalizeAll(domains)
	if err != nil {
		fmt.Fprintln(stderr, "mailguard:", err)
		return exitError
	}
	if len(domains) == 0 {
		fmt.Fprintln(stderr, "mailguard: no domains given (see mailguard -h)")
		return exitError
	}

	checker := &check.Checker{
		Resolver:  resolver.New(opts.server, opts.timeout),
		Selectors: selectorList(opts.selectors),
	}
	reports := checkAll(ctx, checker, domains, opts.concurrency)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "mailguard: interrupted")
		return exitError
	}

	if err := report.Write(stdout, opts.format, reports, !opts.quiet); err != nil {
		fmt.Fprintln(stderr, "mailguard:", err)
		return exitError
	}
	if opts.failUnder != "" {
		for _, r := range reports {
			if !check.GradeAtLeast(r.Grade, opts.failUnder) {
				return exitBelowMin
			}
		}
	}
	return exitOK
}

func parseArgs(args []string, stderr io.Writer) (options, []string, error) {
	var o options
	fs := flag.NewFlagSet("mailguard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `Usage: mailguard [flags] domain...

Checks SPF, DKIM and DMARC for each domain and grades it from A to F.

Examples:
  mailguard example.com example.org
  mailguard -f domains.txt -o csv > report.csv
  cat domains.txt | mailguard -f - -fail-under B

Flags:
`)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.file, "f", "", "read domains from `file`, one per line (\"-\" for stdin)")
	fs.StringVar(&o.format, "o", "table", "output `format`: table, json or csv")
	fs.IntVar(&o.concurrency, "c", 20, "number of domains to check at the same time")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second, "timeout for each DNS query")
	fs.StringVar(&o.server, "dns", "", "DNS `server` to query, e.g. 1.1.1.1 (default: system resolver)")
	fs.StringVar(&o.selectors, "selectors", "", "extra DKIM `selectors` to try, comma-separated")
	fs.StringVar(&o.failUnder, "fail-under", "", "exit with code 2 if any domain grades below `grade` (A-F)")
	fs.BoolVar(&o.quiet, "q", false, "table output: hide the list of issues")
	fs.BoolVar(&o.version, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return o, nil, err
	}

	switch {
	case o.concurrency < 1 || o.concurrency > maxConcurrent:
		return o, nil, fmt.Errorf("-c must be between 1 and %d", maxConcurrent)
	case o.timeout <= 0:
		return o, nil, errors.New("-timeout must be positive")
	case o.failUnder != "" && !check.ValidGrade(o.failUnder):
		return o, nil, fmt.Errorf("-fail-under must be A, B, C, D or F, not %q", o.failUnder)
	}
	if !contains(report.Formats, o.format) {
		return o, nil, fmt.Errorf("-o must be one of %s", strings.Join(report.Formats, ", "))
	}
	return o, fs.Args(), nil
}

// checkAll checks domains with a fixed pool of workers and returns the
// reports in the same order as the input.
func checkAll(ctx context.Context, c *check.Checker, domains []string, workers int) []check.Report {
	reports := make([]check.Report, len(domains))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, len(domains)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				reports[i] = c.Check(ctx, domains[i])
			}
		}()
	}
	for i := range domains {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return reports
}

func readDomains(path string, stdin io.Reader) ([]string, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			domains = append(domains, field)
		}
	}
	return domains, scanner.Err()
}

// normalizeAll validates every domain and removes duplicates, keeping order.
func normalizeAll(inputs []string) ([]string, error) {
	seen := map[string]bool{}
	var out, bad []string
	for _, in := range inputs {
		d, err := check.NormalizeDomain(in)
		if err != nil {
			bad = append(bad, in)
			continue
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("invalid domain(s): %s", strings.Join(bad, ", "))
	}
	return out, nil
}

func selectorList(extra string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(strings.Split(extra, ","), check.DefaultSelectors...) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}
