package check

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/l0phtx/mailguard/internal/resolver"
)

// DefaultSelectors are DKIM selectors used by common mail providers. DKIM
// selectors cannot be listed through DNS, so MailGuard probes these.
var DefaultSelectors = []string{
	"default", "dkim", "mail", "email", "smtp", "k1", "k2", "k3",
	"s1", "s2", "selector1", "selector2", // Microsoft 365
	"google",                                       // Google Workspace
	"20230601", "20221208", "20210112", "20161025", // Gmail and Google-hosted senders
	"mxvault", "mandrill", "mailjet", "zoho", "sendgrid", "smtpapi",
	"everlytickey1", "everlytickey2", "pm", "protonmail", "protonmail2", "protonmail3",
	"fm1", "fm2", "fm3", // Fastmail
	"amazonses", "mesmtp", "sig1", "key1", "dk", "cm",
}

// CheckDKIM probes selectors concurrently and evaluates every key it finds.
func CheckDKIM(ctx context.Context, r resolver.Resolver, domain string, selectors []string) DKIMResult {
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		keys   []DKIMKey
		failed []string
	)
	for _, sel := range selectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			txts, err := resolver.TXT(ctx, r, sel+"._domainkey."+domain)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, sel)
				return
			}
			if key, ok := parseDKIM(sel, strings.Join(txts, "")); ok {
				keys = append(keys, key)
			}
		}(sel)
	}
	wg.Wait()
	sort.Slice(keys, func(i, j int) bool { return keys[i].Selector < keys[j].Selector })

	res := DKIMResult{Keys: keys}
	if len(failed) > 0 && len(keys) == 0 {
		sort.Strings(failed)
		res.Status = StatusError
		res.Issues = []string{fmt.Sprintf("DNS lookups failed for %d selectors (%s)", len(failed), strings.Join(failed, ", "))}
		return res
	}

	active := 0
	weakest := StatusPass
	for _, k := range keys {
		if k.Status == StatusMissing { // revoked key
			continue
		}
		active++
		if severity(k.Status) > severity(weakest) {
			weakest = k.Status
		}
		if k.Note != "" {
			res.Issues = append(res.Issues, fmt.Sprintf("selector %q: %s", k.Selector, k.Note))
		}
	}
	if active == 0 {
		res.Status = StatusMissing
		if revoked := len(keys); revoked > 0 {
			res.Issues = append(res.Issues, fmt.Sprintf("only revoked keys found (%d %s)", revoked, pluralKeys(revoked)))
		}
		res.Issues = append(res.Issues,
			"no active DKIM key at common selectors; if you use a custom selector, pass it with -selectors")
		return res
	}
	res.Status = weakest
	return res
}

// parseDKIM evaluates a DKIM key record. It returns false if txt is not one.
func parseDKIM(selector, txt string) (DKIMKey, bool) {
	tags := parseTags(txt)
	p, hasKey := tags["p"]
	if !hasKey {
		return DKIMKey{}, false
	}
	if v, ok := tags["v"]; ok && !strings.EqualFold(v, "DKIM1") {
		return DKIMKey{}, false
	}

	key := DKIMKey{Selector: selector, KeyType: strings.ToLower(tags["k"])}
	if key.KeyType == "" {
		key.KeyType = "rsa"
	}
	p = strings.Join(strings.Fields(p), "")
	if p == "" {
		key.Status, key.Note = StatusMissing, "key revoked (empty p=)"
		return key, true
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		key.Status, key.Note = StatusFail, "public key is not valid base64"
		return key, true
	}

	switch key.KeyType {
	case "ed25519":
		key.Bits = len(der) * 8
		key.Status = StatusPass
		if len(der) != 32 {
			key.Status, key.Note = StatusFail, "ed25519 key must be 32 bytes"
		}
	case "rsa":
		bits, err := rsaBits(der)
		if err != nil {
			key.Status, key.Note = StatusFail, "could not parse RSA public key"
			return key, true
		}
		key.Bits = bits
		switch {
		case bits < 1024:
			key.Status, key.Note = StatusFail, fmt.Sprintf("%d-bit RSA key can be factored; use 2048 bits", bits)
		case bits < 2048:
			key.Status, key.Note = StatusWeak, fmt.Sprintf("%d-bit RSA key is below the recommended 2048 bits", bits)
		default:
			key.Status = StatusPass
		}
	default:
		key.Status, key.Note = StatusWeak, fmt.Sprintf("unknown key type %q", key.KeyType)
	}
	return key, true
}

var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// rsaBits returns the modulus size of a DER-encoded RSA public key. It decodes
// the ASN.1 by hand because crypto/x509 refuses keys below 1024 bits, and
// those are exactly the keys MailGuard needs to report.
func rsaBits(der []byte) (int, error) {
	var spki subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(der, &spki); err == nil && len(rest) == 0 {
		if !spki.Algorithm.Algorithm.Equal(oidRSAEncryption) {
			return 0, errors.New("not an RSA key")
		}
		der = spki.PublicKey.Bytes
	}
	// Some signers publish a bare PKCS#1 key instead of SubjectPublicKeyInfo.
	var key pkcs1PublicKey
	if rest, err := asn1.Unmarshal(der, &key); err != nil || len(rest) > 0 || key.N == nil || key.N.Sign() <= 0 {
		return 0, errors.New("invalid RSA public key")
	}
	return key.N.BitLen(), nil
}

func pluralKeys(n int) string {
	if n == 1 {
		return "key"
	}
	return "keys"
}

func severity(s Status) int {
	switch s {
	case StatusPass:
		return 0
	case StatusWeak:
		return 1
	default:
		return 2
	}
}
