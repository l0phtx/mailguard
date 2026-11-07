// Package resolver wraps DNS lookups behind an interface so checks can be
// tested without network access.
package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Resolver is the subset of DNS lookups MailGuard needs.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// New returns a Resolver backed by the system resolver, or by a specific DNS
// server such as "1.1.1.1" or "9.9.9.9:53" when server is not empty.
func New(server string, timeout time.Duration) Resolver {
	r := &net.Resolver{PreferGo: true}
	if server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
		}
		dialer := net.Dialer{Timeout: timeout}
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, server)
		}
	}
	return &timeoutResolver{r: r, timeout: timeout}
}

type timeoutResolver struct {
	r       *net.Resolver
	timeout time.Duration
}

func (t *timeoutResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.r.LookupTXT(ctx, name)
}

func (t *timeoutResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.r.LookupMX(ctx, name)
}

// IsNotFound reports whether err means the name or record does not exist
// (NXDOMAIN or NODATA), as opposed to a timeout or server failure.
func IsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// TXT looks up TXT records and treats "not found" as an empty answer.
func TXT(ctx context.Context, r Resolver, name string) ([]string, error) {
	records, err := r.LookupTXT(ctx, name)
	if err != nil && !IsNotFound(err) {
		return nil, err
	}
	return records, nil
}
