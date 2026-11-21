# AS149794 IP Geofeed

Public IPv4 and IPv6 geolocation data for geofeed consumers and network operators.

**Publication:** [geofeed.csv](https://raw.githubusercontent.com/daryll-swer/ip-geofeed/main/geofeed.csv)

**Operator URL:** [www.daryllswer.com/geofeed](https://www.daryllswer.com/geofeed)

The publication follows the repository's `main` branch. APNIC registration supplies the authoritative discovery reference; the validator does not hardcode either publication URL.

## Checks

| Check | Purpose | Merge requirement |
| --- | --- | --- |
| Local validation | Parse proposed data, validate policy and run offline tests | Required `validate` check |
| Live audit | Check APNIC authority, selected feeds and observed AS149794 route authorisation | Non-blocking |
| Publication verification | Compare managed published feeds with accepted file bytes | Post-publication, non-blocking |

New prefixes need not already be published or visible in BGP. Owned address space may be dormant or leased to another ASN. Third-party address space needs routing-authorisation evidence within the actual leased range.

Blank location fields are intentional for some prefixes. Postal codes and nested, more-specific location entries are preserved. Actual geographic accuracy remains the operator's responsibility.

## Local Validation

Use Python 3.10 or newer and an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
.venv/bin/python scripts/validate_geofeed.py geofeed.csv
.venv/bin/python -m unittest discover -s tests
```

The pinned ISO dataset is used offline during validation. Local checks do not need APNIC or RIPEstat to be available.

To run the separate live audit:

```bash
.venv/bin/python scripts/check_authority.py --geofeed geofeed.csv --asn 149794
```

Live results distinguish invalid evidence from unavailable or incomplete checks. No observed BGP routes is a warning, not proof of an outage or successful RPKI validation.

## Publication and Limitations

This repository publishes CRLF line endings. Independent feeds using LF remain readable with a warning. Publication verification preserves exact file bytes and allows up to two hours for convergence; superseded revisions do not replace newer findings.

The workflow definitions provide weekly live audits on Saturday at 12:00 IST, manual runs and change-triggered checks. Trusted runs maintain one tracking issue for warnings, failures and incomplete results. Scheduled execution is best effort; local edits do not activate these workflows until separately approved publication.

The geofeed remains unsigned. Plaintext WHOIS URL discovery, collector visibility and operator-supplied geographic truth remain explicit limitations. See [the current design and trust boundaries](docs/adr/0002-independent-validation-and-publication.md) for details.

## For AI Agents

Start with [agent instructions](AGENTS.md) and [task state](PLANS.md).
