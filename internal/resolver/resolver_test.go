package resolver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(&net.DNSError{IsNotFound: true}) {
		t.Error("NXDOMAIN should be not found")
	}
	if IsNotFound(&net.DNSError{IsTimeout: true}) || IsNotFound(errors.New("boom")) || IsNotFound(nil) {
		t.Error("timeouts and other errors are not 'not found'")
	}
}

func TestTXT(t *testing.T) {
	f := &Fake{
		TXTRecords: map[string][]string{"example.com": {"v=spf1 -all"}},
		Errors:     map[string]error{"broken.com": errors.New("server misbehaving")},
	}
	ctx := context.Background()
	if got, err := TXT(ctx, f, "EXAMPLE.com."); err != nil || len(got) != 1 {
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := TXT(ctx, f, "missing.com"); err != nil || got != nil {
		t.Errorf("missing name should be an empty answer, got %v, %v", got, err)
	}
	if _, err := TXT(ctx, f, "broken.com"); err == nil {
		t.Error("lookup errors must be returned")
	}
}

func TestNewAddsDefaultPort(t *testing.T) {
	for _, server := range []string{"", "1.1.1.1", "9.9.9.9:53", "[2606:4700:4700::1111]"} {
		if New(server, time.Second) == nil {
			t.Errorf("New(%q) returned nil", server)
		}
	}
}
