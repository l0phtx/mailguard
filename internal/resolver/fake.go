package resolver

import (
	"context"
	"net"
	"strings"
)

// Fake is an in-memory Resolver for tests. Names are matched case-insensitively
// and without a trailing dot.
type Fake struct {
	TXTRecords map[string][]string
	MXRecords  map[string][]*net.MX
	Errors     map[string]error
}

func (f *Fake) LookupTXT(_ context.Context, name string) ([]string, error) {
	key := normalize(name)
	if err, ok := f.Errors[key]; ok {
		return nil, err
	}
	if records, ok := f.TXTRecords[key]; ok {
		return records, nil
	}
	return nil, notFound(name)
}

func (f *Fake) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	key := normalize(name)
	if err, ok := f.Errors["mx:"+key]; ok {
		return nil, err
	}
	if records, ok := f.MXRecords[key]; ok {
		return records, nil
	}
	return nil, notFound(name)
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
