package check

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/l0phtx/mailguard/internal/resolver"
)

// rsaKey returns a base64 SubjectPublicKeyInfo with a modulus of the given
// size. The modulus is random, not a real key: only its length matters here,
// and crypto/rsa refuses to generate keys below 1024 bits.
func rsaKey(t *testing.T, bits int) string {
	t.Helper()
	n, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{n, 65537})
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
		asn1.BitString{Bytes: pub, BitLength: len(pub) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestParseDKIM(t *testing.T) {
	pkcs1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&pkcs1Key.PublicKey))
	realDER, err := x509.MarshalPKIXPublicKey(&pkcs1Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	realKey := base64.StdEncoding.EncodeToString(realDER)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed := base64.StdEncoding.EncodeToString(edPub)
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	edSPKI := base64.StdEncoding.EncodeToString(edDER)

	tests := []struct {
		name   string
		txt    string
		ok     bool
		status Status
		bits   int
	}{
		{"rsa 2048", "v=DKIM1; k=rsa; p=" + rsaKey(t, 2048), true, StatusPass, 2048},
		{"rsa 1024", "v=DKIM1; p=" + rsaKey(t, 1024), true, StatusWeak, 1024},
		{"rsa 512", "v=DKIM1; k=rsa; p=" + rsaKey(t, 512), true, StatusFail, 512},
		{"pkcs1 key", "k=rsa; p=" + pkcs1, true, StatusPass, 2048},
		{"real x509 key", "v=DKIM1; k=rsa; p=" + realKey, true, StatusPass, 2048},
		{"ed25519", "v=DKIM1; k=ed25519; p=" + ed, true, StatusPass, 256},
		{"revoked", "v=DKIM1; p=", true, StatusMissing, 0},
		{"bad base64", "v=DKIM1; p=!!!", true, StatusFail, 0},
		{"garbage key", "v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("nope")), true, StatusFail, 0},
		{"ed25519 key in rsa record", "v=DKIM1; k=rsa; p=" + edSPKI, true, StatusFail, 0},
		{"not dkim", "v=spf1 -all", false, "", 0},
		{"wrong version", "v=DKIM2; p=abc", false, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ok := parseDKIM("sel", tt.txt)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if key.Status != tt.status || key.Bits != tt.bits {
				t.Errorf("got status %s bits %d, want %s %d (%s)", key.Status, key.Bits, tt.status, tt.bits, key.Note)
			}
		})
	}
}

func TestCheckDKIM(t *testing.T) {
	strong, weak := rsaKey(t, 2048), rsaKey(t, 1024)
	selectors := []string{"google", "selector1", "selector2", "s1"}

	t.Run("weakest active key wins", func(t *testing.T) {
		r := &resolver.Fake{TXTRecords: map[string][]string{
			"selector1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + strong},
			"selector2._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + weak},
			"s1._domainkey.example.com":        {"v=DKIM1; p="},
		}}
		got := CheckDKIM(context.Background(), r, "example.com", selectors)
		if got.Status != StatusWeak || len(got.Keys) != 3 {
			t.Fatalf("got %s with %d keys", got.Status, len(got.Keys))
		}
		if got.Keys[0].Selector != "s1" {
			t.Errorf("keys are not sorted: %v", got.Keys)
		}
	})

	t.Run("record split across strings", func(t *testing.T) {
		r := &resolver.Fake{TXTRecords: map[string][]string{
			"google._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + strong[:100], strong[100:]},
		}}
		if got := CheckDKIM(context.Background(), r, "example.com", selectors); got.Status != StatusPass {
			t.Fatalf("status = %s, issues %v", got.Status, got.Issues)
		}
	})

	t.Run("only revoked keys", func(t *testing.T) {
		r := &resolver.Fake{TXTRecords: map[string][]string{"s1._domainkey.example.com": {"v=DKIM1; p="}}}
		got := CheckDKIM(context.Background(), r, "example.com", selectors)
		if got.Status != StatusMissing || !hasIssue(got.Issues, "only revoked keys found (1 key)") {
			t.Fatalf("got %s %v", got.Status, got.Issues)
		}
	})

	t.Run("nothing found", func(t *testing.T) {
		got := CheckDKIM(context.Background(), &resolver.Fake{}, "example.com", selectors)
		if got.Status != StatusMissing || !hasIssue(got.Issues, "-selectors") {
			t.Fatalf("got %s %v", got.Status, got.Issues)
		}
	})

	t.Run("dns failures", func(t *testing.T) {
		r := &resolver.Fake{Errors: map[string]error{"google._domainkey.example.com": errors.New("timeout")}}
		if got := CheckDKIM(context.Background(), r, "example.com", selectors); got.Status != StatusError {
			t.Fatalf("status = %s", got.Status)
		}
	})
}
