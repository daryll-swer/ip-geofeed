# ADR 0001: Geofeed CI authority and RPKI validation

Date: 2026-06-30

Status: Accepted

## Context

This repository publishes the public RFC 8805 geofeed for AS149794.

Canonical publication path:

- Operator geofeed URL: `https://www.daryllswer.com/geofeed`
- GitHub raw CSV target: `https://raw.githubusercontent.com/daryll-swer/ip-geofeed/main/geofeed.csv`

The APNIC WHOIS `geofeed:` attribute is expected to point at the operator geofeed URL.

Some prefixes may exist in APNIC WHOIS, RPKI, IRR, and the geofeed file without currently appearing in the live global BGP table. Therefore geofeed authority checks and live-route RPKI checks must be separate.

## Decision

CI validates three independent properties:

1. `geofeed.csv` syntax is valid and conservative.
2. Every geofeed prefix is covered by an APNIC `inetnum` or `inet6num` object with the expected `geofeed:` URL.
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

- RFC 8805: A Format for Self-Published IP Geolocation Feeds
- RFC 9632: Finding and Using Geofeed Data
- APNIC WHOIS geofeed publication practice
- RIPEstat `bgp-state` API
- RIPEstat `rpki-validation` API
