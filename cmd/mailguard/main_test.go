package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	content := "# company domains\nexample.com\nexample.org, example.net\n\n  shop.example.com  # store\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readDomains(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "example.com example.org example.net shop.example.com"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v", got)
	}

	fromStdin, err := readDomains("-", strings.NewReader("a.com\nb.com\n"))
	if err != nil || len(fromStdin) != 2 {
		t.Errorf("stdin: %v %v", fromStdin, err)
	}
}

func TestNormalizeAll(t *testing.T) {
	got, err := normalizeAll([]string{"Example.com", "example.com.", "user@example.org"})
	if err != nil || strings.Join(got, ",") != "example.com,example.org" {
		t.Errorf("got %v, %v", got, err)
	}
	if _, err := normalizeAll([]string{"ok.com", "not a domain"}); err == nil {
		t.Error("expected an error")
	}
}

func TestSelectorList(t *testing.T) {
	got := selectorList(" Custom , google,")
	if got[0] != "custom" || got[1] != "google" {
		t.Errorf("custom selectors should come first: %v", got[:3])
	}
	seen := map[string]int{}
	for _, s := range got {
		seen[s]++
		if seen[s] > 1 {
			t.Errorf("duplicate selector %q", s)
		}
	}
}

func TestRunErrors(t *testing.T) {
	cases := map[string][]string{
		"no domains":     {},
		"bad format":     {"-o", "xml", "example.com"},
		"bad grade":      {"-fail-under", "E", "example.com"},
		"bad workers":    {"-c", "0", "example.com"},
		"invalid domain": {"not_a_domain"},
		"missing file":   {"-f", "/nonexistent/domains.txt"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, strings.NewReader(""), &stdout, &stderr); code != exitError {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitError, stderr.String())
			}
			if stderr.Len() == 0 {
				t.Error("expected an error message")
			}
		})
	}
}

func TestRunVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(stdout.String(), "mailguard ") {
		t.Errorf("version output = %q", stdout.String())
	}
	if code := run(context.Background(), []string{"-h"}, nil, &stdout, &stderr); code != exitOK {
		t.Errorf("-h exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage: mailguard") {
		t.Error("help text missing")
	}
}
