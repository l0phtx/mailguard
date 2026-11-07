# MailGuard

[![CI](https://github.com/l0phtx/mailguard/actions/workflows/ci.yml/badge.svg)](https://github.com/l0phtx/mailguard/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/l0phtx/mailguard.svg)](https://pkg.go.dev/github.com/l0phtx/mailguard)
![License](https://img.shields.io/badge/license-MIT-green)

MailGuard checks SPF, DKIM and DMARC for a list of domains at the same time and grades each one from A to F.

Spoofed email is still the easiest way into most companies. These three DNS records decide whether a receiving mail server can tell a real message from a forged one. MailGuard reads them from public DNS, finds the mistakes that quietly break them, and tells you what to fix. It sends no email and touches no server except DNS, so it is safe to run against any domain.

```
$ mailguard example.com microsoft.com cloudflare.com paypal.com github.com
DOMAIN          GRADE  SCORE  SPF          DKIM           DMARC
example.com     A      100    pass (-all)  pass           pass (p=reject)
microsoft.com   B      87     pass (-all)  weak (1 key)   pass (p=reject)
cloudflare.com  B      87     pass (-all)  weak (4 keys)  pass (p=reject)
paypal.com      B      82     pass (~all)  weak (2 keys)  pass (p=reject)
github.com      C      72     pass (~all)  weak (9 keys)  pass (p=quarantine)

example.com
  - MX: null MX (RFC 7505): domain declares that it accepts no mail
  - DKIM: no DKIM needed for a domain that does not send mail
  - DMARC: no rua= address, so you receive no reports about who sends as your domain

github.com
  - SPF: "~all" (softfail) marks spoofed mail as suspicious; "-all" rejects it
  - DKIM: selector "selector1": 1024-bit RSA key is below the recommended 2048 bits
  - DMARC: p=quarantine sends spoofed mail to spam; p=reject blocks it
  ...
```

*Real output from November 2026; DNS records change over time.*

## What it checks

| Check | What MailGuard looks for |
| --- | --- |
| **SPF** | Exactly one `v=spf1` record. The final `all` qualifier (`-all`, `~all`, `?all`, `+all`). Follows every `include:` and `redirect=` and counts DNS lookups against the RFC 7208 limit of 10. Include loops, includes that point to a domain with no SPF, invalid terms and the deprecated `ptr` mechanism. |
| **DKIM** | Probes 30+ selectors used by Google Workspace, Microsoft 365, Mailchimp, SendGrid, Amazon SES, Proton, Fastmail and others, concurrently. Decodes each public key and reports its type and size (RSA below 1024 bits fails, below 2048 is weak). Revoked keys (`p=`) are recognized. |
| **DMARC** | Exactly one `v=DMARC1` record at `_dmarc.<domain>`. The policy (`p=reject`, `quarantine` or `none`), `pct=` below 100, the subdomain policy `sp=` and missing `rua=` report addresses. If a subdomain has no record, MailGuard uses the closest parent record and its `sp=` policy, found by walking up the DNS tree (DMARCbis). |
| **MX** | The mail servers, and null MX (RFC 7505). A domain that receives no mail does not need DKIM, but it still needs `v=spf1 -all` and `p=reject` so nobody can spoof it. |

### Grading

Each domain gets a score out of 100:

| Check | Points |
| --- | --- |
| SPF | 30 for `-all`, 25 for `~all`, 10 if weak, 0 if missing or broken |
| DKIM | 25 if every key is strong, 12 if a key is weak, 0 if none is found |
| DMARC | 45 for `p=reject`, 35 for `p=quarantine`, 10 for `p=none`; minus 10 if `pct` is below 100 |

DMARC weighs most because it is the only record that tells receivers what to do when SPF and DKIM fail.

| Grade | Score |
| --- | --- |
| A | 90-100 |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | below 40 |

## Install

Download a binary for Linux, macOS or Windows from the [releases page](https://github.com/l0phtx/mailguard/releases), or build it with Go 1.23+:

```bash
go install github.com/l0phtx/mailguard/cmd/mailguard@latest
```

## Usage

```bash
mailguard example.com example.org            # check domains
mailguard alice@example.com                  # email addresses and URLs work too
mailguard -f domains.txt                     # one domain per line, # for comments
cat domains.txt | mailguard -f -             # read from stdin
mailguard -f domains.txt -o csv > report.csv # spreadsheet
mailguard -o json example.com | jq '.[0].spf'
mailguard -selectors mycorp2024 example.com  # add your own DKIM selector
mailguard -dns 1.1.1.1 example.com           # use a specific resolver
```

| Flag | Default | Description |
| --- | --- | --- |
| `-f file` | | Read domains from a file (`-` for stdin) |
| `-o format` | `table` | `table`, `json` or `csv` |
| `-c n` | `20` | Domains checked at the same time |
| `-timeout d` | `5s` | Timeout for each DNS query |
| `-dns server` | system | DNS server, e.g. `1.1.1.1` or `9.9.9.9:53` |
| `-selectors list` | | Extra DKIM selectors, comma-separated |
| `-fail-under grade` | | Exit with code 2 if any domain grades below `A`-`F` |
| `-q` | off | Table output: hide the list of issues |
| `-version` | | Print the version |

### Use it in CI

Fail a pipeline when one of your domains drops below a B:

```yaml
- run: go install github.com/l0phtx/mailguard/cmd/mailguard@latest
- run: mailguard -fail-under B -f domains.txt
```

Exit codes: `0` success, `1` usage or input error, `2` a domain graded below `-fail-under`.

## How it works

```
 domains.txt ─┐
              v
        +-----------+   jobs   +----------+----------+----------+
        | main.go   |--------->| worker 1 | worker 2 | worker N |   (-c workers)
        | dedupe,   |          +----+-----+----------+----------+
        | validate  |               |
        +-----------+               v  one domain
                         +----------+-----------+-----------+
                         v          v           v           v
                       CheckMX   CheckSPF   CheckDKIM   CheckDMARC   (goroutines)
                                 includes   30+ selectors
                                 followed   in parallel
                         +----------+-----------+-----------+
                                    v
                              Grade() -> Report -> table / JSON / CSV
```

- **Two levels of concurrency.** A fixed pool of workers takes domains from a channel. Inside each domain, the four checks run as goroutines, and DKIM probes all selectors in parallel. Results are written to a slice by index, so output keeps the input order without sorting.
- **Bounded work.** The worker count caps open DNS queries, every query has its own timeout, and Ctrl+C cancels everything through a shared `context.Context`.
- **Testable DNS.** All lookups go through a small `Resolver` interface. Tests use an in-memory fake, so the whole suite runs offline in under a second.
- **Errors are not failures.** A broken record (two SPF records, a bad DMARC policy) is graded `fail`. A DNS timeout is reported as `error`, so a flaky resolver never looks like a misconfigured domain.

```
cmd/mailguard/      flags, input parsing, worker pool, exit codes
internal/check/     SPF, DKIM, DMARC and MX checks, grading
internal/report/    table, JSON and CSV output
internal/resolver/  DNS interface, system resolver and test fake
```

## Limitations

- DNS cannot list DKIM selectors. If your provider uses a custom one, pass it with `-selectors`, or MailGuard reports DKIM as missing.
- MailGuard checks what is published in DNS. It does not send mail, so it cannot confirm that your servers actually sign messages.
- MailGuard can only see what your resolver returns. Some NAT and VM resolvers (VMware Fusion's NAT DNS, for example) silently drop records from large TXT answers without setting the truncation bit, which makes a real SPF record look missing. If results look wrong, query a public resolver directly with `-dns 1.1.1.1`.
- SPF macros (`%{i}`) depend on the sender and are not expanded. They are reported, and their lookups are not counted.

## Development

```bash
make test    # go test -race ./...
make cover   # coverage summary
make lint    # gofmt + go vet
make build   # ./mailguard with the version from git
```

## License

[MIT](LICENSE)
