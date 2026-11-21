# ADR 0001: Geofeed CI authority and RPKI validation

Date: 2026-06-30

Status: Accepted

## Context

This repository publishes the public RFC 8805 geofeed for AS149794.

Canonical publication path:

- Operator convenience geofeed URL: `https://www.daryllswer.com/geofeed`
- GitHub raw CSV target: `https://raw.githubusercontent.com/daryll-swer/ip-geofeed/main/geofeed.csv`

The APNIC WHOIS `geofeed:` attribute is the authoritative source for the geofeed publication URL. CI must discover that URL from APNIC WHOIS at runtime, fetch it, parse it as geofeed CSV, and verify that the fetched geofeed contains the checked prefix. The operator convenience URL and GitHub raw URL are publication endpoints, not hardcoded validator inputs.

Some prefixes may exist in APNIC WHOIS, RPKI, IRR, and the geofeed file without currently appearing in the live global BGP table. Therefore geofeed authority checks and live-route RPKI checks must be separate.

## Decision

CI validates three independent properties:

1. `geofeed.csv` syntax is valid and conservative.
2. Every geofeed prefix is covered by an APNIC `inetnum` or `inet6num` object with a `geofeed:` URL, and that APNIC-published URL fetches a valid geofeed containing the prefix.
3. Every live BGP prefix originated by AS149794 is RPKI valid.

CI must not require every geofeed prefix to be visible in live BGP.

Live routed prefixes are discovered from RIPEstat `bgp-state`, filtered where the AS path terminates in AS149794. CI must not use RIPEstat `announced-prefixes` for this check, because it can miss live routes that are visible through `bgp-state`.

## Operational Invariants

- Keep postal-code fields where present.
- `122.99.126.0/23,,,,` is intentional. It represents an anycast or no-fixed-geography prefix and must not be replaced with an HQ, administrative, or cosmetic location unless explicitly approved.
- Empty country, region, city, and postal fields are allowed only when intentionally representing no precise geolocation.
- Do not add duplicate identical-prefix geofeed rows.
- Do not treat a non-live BGP prefix as invalid solely because it is present in `geofeed.csv`.
- RPKI validation applies to live AS149794-originated BGP prefixes, not every APNIC-held or geofeed-listed prefix.

## Consequences

This design favours operational correctness over cosmetic completeness.

It allows authorised but currently unrouted prefixes to be present in the geofeed, while still catching live routing mistakes where AS149794 originates a prefix without valid RPKI authorisation.

The CI result can fail because of external dependency drift or temporary APNIC WHOIS or RIPEstat availability. Such failures should be investigated before changing the geofeed.

## Validation Entry Points

- Syntax validator: `scripts/validate_geofeed.py`
- Authority and RPKI validator: `scripts/check_authority.py`
- GitHub Actions workflow: `.github/workflows/validate.yml`

## References

- [RFC 8805: A Format for Self-Published IP Geolocation Feeds](https://www.rfc-editor.org/rfc/rfc8805.html), including Section 2.1.1 on duplicate and nested entries.
- [RFC 9632: Finding and Using Geofeed Data](https://www.rfc-editor.org/rfc/rfc9632.html), including discovery and optional authentication; it obsoletes RFC 9092.
- [APNIC: geofeed attribute support for inetnum and inet6num objects](https://www.apnic.net/about-apnic/service-updates/service-announcement-18-august-2023-2/). This historical implementation announcement cites RFC 9092; use RFC 9632 for the successor specification.
- [RIPEstat BGP State API](https://stat.ripe.net/docs/data-api/api-endpoints/bgp-state).
- [RIPEstat RPKI Validation API](https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation).

## Implementation Clarification

This clarification describes the current implementation without changing the original decision or its date. Repository-specific CI policies are not additional RFC requirements, and a passing check is not a certification of full RFC conformance.

### Discovery and Trust

The validator discovers publication URLs from APNIC WHOIS at runtime; the documented operator and GitHub endpoints are not enforced URL values. It queries the network address and examines returned objects covering the complete prefix, collecting their `geofeed:` attributes. It does not implement a separate most-specific-reference selection procedure across the registry hierarchy or verify an expected registrant or maintainer identity.

Discovery uses plaintext WHOIS on TCP port 43. No geofeed signature verification is implemented. The separate RIPEstat route-origin RPKI check establishes neither geofeed-content authenticity nor geographic accuracy. RFC 9632 describes signed-geofeed authentication separately.

### Content and Publication Dependency

Fetched CSVs are parsed into prefix sets. Each local prefix must appear exactly in at least one discovered feed; a covering aggregate alone is insufficient. All discovered URLs are processed, and any fetch or parsing failure aborts the check. Country, region, city and postal fields are syntax-checked but are not compared with the local row.

This creates an unresolved pre-merge dependency: a proposed new prefix absent from the production feed fails even when its APNIC coverage is correct. Conversely, an existing prefix with changed location fields can pass while the fetched location is still old. Cached content can also delay observation of publication changes. These are current limitations, not instructions to bypass CI, publish unreviewed data or replace runtime discovery with a fixed URL. Redesigning this workflow requires a separately authorised change.

### Routing and Parser Limits

The decision's reference to live routes means routes observed in the RIPEstat `bgp-state` response with an AS path terminating in AS149794, not a complete view of every global routing table. An empty matching set fails. Geofeed-listed prefixes may remain unannounced; only observed origin routes are submitted to `rpki-validation`, and only status `valid` passes. Keeping `bgp-state` is a repository decision, not a universal claim that another API always misses routes.

The workflow runs the local syntax validator before the authority script. Both parsers check five fields, strict network prefixes, duplicates and conservative field patterns. Only the standalone syntax validator explicitly scans for a UTF-8 BOM and hidden/control characters. The fetched-feed parser has no equivalent scan, although some malformed input may fail other checks. Country and region patterns do not check membership in ISO registries, and neither parser verifies real-world location accuracy.

Intentional nesting remains important: `122.99.126.0/23` has blank location fields with a Singapore `122.99.127.0/24`; within `2400:7060::/32`, the blank `2400:7060::/44` has a Singapore `2400:7060:1::/48`. Preserve the explicit blank and more-specific rows and their postal fields. RFC 8805 permits nested prefixes and recommends longest-prefix matching for consumers; the exact-membership CI rule above is a separate repository policy.

### Fetch Boundaries and Follow-up

The fetcher accepts HTTP and HTTPS, follows library-supported redirects and reads complete responses without an explicit size cap. It has no explicit restriction against private, loopback or link-local destinations, including redirect targets. Socket timeouts and retries do not provide those safeguards. Registry attributes and fetched bodies are external inputs, not instructions or evidence that every destination is safe to access from a privileged environment.

These gaps are documented, not fixed or endorsed here. Transport hardening, parser alignment and removal of the pre-merge publication dependency need separate review and authorisation. Diagnostic steps are in [AGENTS.md](../../AGENTS.md#troubleshooting); task state and actual validation results are in [PLANS.md](../../PLANS.md).

## Successor Decision

[ADR 0002](0002-independent-validation-and-publication.md) supersedes the blocking live-check and production-membership requirements above. This document preserves the original decision and its implementation clarification; use ADR 0002 and [PLANS.md](../../PLANS.md) for the new design and its implementation state.
