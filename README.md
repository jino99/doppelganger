# doppelganger

Typosquat permutation scanner. Generates algorithmic lookalikes of a domain, resolves them over plain DNS, inspects their TLS certificates, and classifies each hit — without API keys, external databases, or third-party services.

Single file. Python 3.8+. Standard library only.

## What it does

For a domain such as `example.com`, `doppelganger` generates hundreds of algorithmic permutations (bitsquatting, homoglyphs, omission, insertion, transposition, hyphenation, combosquatting, TLD swaps, IDN lookalikes, subdomain prefixes, leetspeak, country prefixes), then for each candidate:

1. Resolves `A`, `AAAA`, `MX`, and `SOA` records
2. Performs a TLS handshake on `:443` when the candidate has an address
3. Classifies the result into one of eight buckets and sorts them by suspicion

The tool is designed to be run once for a snapshot, or as a daemon that reports only new findings.

## Requirements

- Python 3.8 or later
- A working DNS resolver (system default, or specify one with `-r`)
- Network access to `:53` (UDP and TCP) and `:443`

No installation, no `pip install`, no virtualenv. Download the file, make it executable, run it.

```sh
curl -O https://raw.githubusercontent.com/jino99/doppelganger/main/doppelganger.py
chmod +x doppelganger.py
./doppelganger.py example.com
```

## Usage

```
doppelganger <domain> [options]
```

### Single scan

```sh
doppelganger example.com
```

```
doppelganger — permutation scan of example.com
[*] 547 permutations generated, 272 resolved in 50.34s

[+] ACTIVE — trusted TLS (97)
  m1crosoft.co                               homoglyph-tld-swap trusted issuer=YR1
  nnicrosoft.com                             homoglyph          trusted issuer=GoDaddy TLS Intermediate CA DV - R1v1
  micr0soft.io                               homoglyph-tld-swap trusted issuer=YE1
  ...

[+] ACTIVE — untrusted TLS (15)
  micorsoft.com                              transposition      untrusted
  auth-microsoft.com                         combosquatting     untrusted
  microsoft-secure.com                       combosquatting     untrusted
  ...

[+] ACTIVE — no HTTPS on :443 (49)
  ...

[i] SELF-SUBDOMAIN — resolves to your own infra (110)
  account.microsoft.com                      subdomain-insert   a=23.60.189.162 ...
  ...
```

### Triage mode

Hide the noise. Only shows phishing, untrusted TLS, and typosquats with a targeted name pattern (homoglyph, leet, bitsquat, single-char typo). Untrusted TLS is listed before trusted.

```sh
doppelganger example.com --only-suspicious
```

```
doppelganger — permutation scan of example.com
[*] 547 permutations generated, 272 resolved in 50.55s (showing only suspicious)

[+] ACTIVE — untrusted TLS (16)
  micro5oft.com                              homoglyph/partial-leetspeak untrusted
  xn--micrsoft-p3a.com                       homoglyph          untrusted [MIXED-SCRIPT,IDN:micròsoft.com]
  micorsoft.com                              transposition      untrusted
  auth-microsoft.com                         combosquatting     untrusted
  microsoft-secure.com                       combosquatting     untrusted
  ...

[+] ACTIVE — trusted TLS (80)
  m1crosoft.co                               homoglyph-tld-swap trusted issuer=YR1
  nnicrosoft.com                             homoglyph          trusted issuer=GoDaddy TLS Intermediate CA DV - R1v1
  ...

[+] ACTIVE — no HTTPS on :443 (23)
  ...
```

### Machine-readable

```sh
doppelganger example.com --json
```

Emits a single JSON document with a `summary` object and a `findings` array. Each finding includes `name`, `kinds`, `status`, `a`, `aaaa`, `mx`, `soa`, `tls` (if handshake succeeded), and `unicode`/`mixed_script` for IDN candidates. The root object also carries `filter` (set to `suspicious-only` when `--only-suspicious` is used).

### Persistent mode

Run as a daemon, emitting only findings that are new or whose state has changed since the previous cycle.

```sh
doppelganger example.com -p --interval 3600 -s state.json
```

The first cycle writes a baseline to the state file and prints nothing. Subsequent cycles compare against the baseline and write only deltas to stdout. The state file is rewritten atomically after each cycle, so a crash mid-write cannot corrupt it.

Combine with `--only-suspicious` to alert only on targeted lookalikes:

```sh
doppelganger example.com -p --only-suspicious --json | tee -a alerts.jsonl
```

Each line of stdout is a self-contained JSON object prefixed with a `ts` field, suitable for appending to a log file or piping into a downstream consumer.

### Pruning stale entries

Over time, entries that stop resolving remain in the state file with an old `last_seen` timestamp. By default they are kept. To bound state growth, prune entries not seen in the last N days:

```sh
doppelganger example.com -p --prune-after-days 30 -s state.json
```

Pruning runs once per cycle, after deltas are computed and before the state file is saved. Removed entries are logged on stderr (`pruned N stale finding(s)`). Default is `0` (never prune).

### Skip TLS

Faster DNS-only scan. Trade-off: active hosts are no longer distinguished by certificate validity, and ownership signals from TLS are lost.

```sh
doppelganger example.com --no-tls
```

## Flags

| Flag | Description |
|---|---|
| `<domain>` | Target domain (e.g. `example.com`). Optional; running without arguments prints help. |
| `-p`, `--persistent` | Daemon mode. Baseline on first cycle, deltas thereafter. Requires a state file. |
| `--interval SEC` | Seconds between cycles in `-p`. Default: 3600. |
| `--prune-after-days N` | In `-p`, remove entries not seen in N days. Default: 0 (never prune). |
| `-s`, `--state FILE` | State file path. Default: `doppelganger-<domain>.json`. |
| `-j`, `--json` | JSON output (single run) or JSONL new-findings (`-p`). |
| `--only-suspicious` | Filter to phishing, untrusted TLS, and targeted typosquats. Untrusted first. |
| `--no-tls` | Skip TLS probing. |
| `--dns-timeout SEC` | DNS query timeout. Default: 3. |
| `--tls-timeout SEC` | TLS handshake timeout. Default: 5. |
| `--workers N` | Concurrent workers. Default: 16. Range: 1–256. |
| `-r`, `--resolver IP` | DNS resolver. Repeatable or comma-separated. Default: system. Use `1.1.1.1` or `8.8.8.8` if your ISP filters malicious domains. |
| `-q`, `--quiet` | Suppress progress logs on stderr. |

## Classification

Every finding is assigned exactly one status.

| Status | Meaning | Action |
|---|---|---|
| `self_subdomain` | The target owns this name. Proven via SOA, IP subset, or a trusted certificate that carries the target's brand on a structural permutation. | None |
| `phishing` | A trusted certificate carries the target's brand, but the permutation is a typo, homoglyph, or combosquat. | Investigate immediately |
| `trusted_tls` | A valid certificate exists for the permutation's own name. Typically a registered lookalike. | Triage by kind and issuer |
| `untrusted_tls` | An invalid certificate (self-signed, expired, mismatched). Often a typosquat whose HTTPS is broken. | Investigate |
| `active_no_https` | Resolves, but no TLS handshake succeeds on `:443`. | Usually parked or stale |
| `mail_only` | Has `MX` records but no `A`/`AAAA`. | Mail-capable; check SPF/DKIM |
| `active` | Resolves with `A`/`AAAA` but TLS was not checked (`--no-tls`). | Re-run with TLS to disambiguate |
| `registered` | Resolves but returns no address or mail records. | Low priority |

Within the `trusted_tls` and `untrusted_tls` buckets, entries are sorted by suspicion (homoglyph first, combosquat last). This ordering reflects likelihood that the permutation is a deliberate attack rather than a benign registration.

## How ownership is detected

`doppelganger` does not use WHOIS, ASN lookup, or any external service. Three signals, all derived from DNS and TLS:

1. **SOA rname**: if the zone's SOA rname lives inside the target's zone (e.g. `hostmaster.microsoft.com` for the zone `micros0ft.net`), the zone is under the target's administrative control.
2. **IP subset**: for subdomain-insertion permutations (`login.example.com`), if the permutation's addresses are a subset of the target's addresses, it resolves to the target's infrastructure.
3. **Certificate brand claim**: a *trusted* certificate whose SAN carries the target's domain, combined with a structural kind (`subdomain-insert` or `tld-swap`), is cryptographic proof of ownership — only the target can pass CA validation for those names.

The combination is robust against arbitrary typosquatters, who cannot forge SOA rname, cannot point their names at Microsoft's IPs, and cannot obtain a trusted certificate claiming `microsoft.com`.

## Design notes & trade-offs

- **SOA rname is spoofable in principle**. An attacker who controls their own zone can set the SOA rname to `hostmaster.example.com` and trick the ownership check. In practice this requires deliberate evasion and is rare. The IP-subset and certificate-brand signals are not spoofable and remain authoritative.
- **Sinkholed resolvers may hide permutations**. Some public resolvers filter known-malicious domains. Use `-r` to point at an unfiltered recursive resolver (`1.1.1.1` or `8.8.8.8`).
- **Certificate inspection is unverified for untrusted certs**. When the TLS handshake fails verification, only `trusted: false` is recorded. Issuer and SAN are not extracted from the raw DER.
- **No wildcard TXT or CAA checks**. Only the record types listed above are queried.
- **Persistent mode does not prune by default**. Entries that stop resolving remain in the state file with an old `last_seen` timestamp. Use `--prune-after-days N` to bound state growth.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished successfully, or `--only-suspicious` produced no output. |
| `2` | Usage error, configuration error, or state file could not be read. |
| `130` | Interrupted (SIGINT / Ctrl-C). |

## Development

The file is self-contained and self-executable. Run it directly:

```sh
./doppelganger.py example.com --only-suspicious
```

No build step, no test suite, no dependencies to install.

## License

MIT. See [LICENSE](LICENSE).