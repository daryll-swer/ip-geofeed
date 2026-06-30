# AGENTS.md

## Purpose

This repository publishes the public RFC 8805 geofeed for AS149794.

Future agents should treat this repository as operational network data, not a generic CSV project. Preserve operational correctness over cosmetic geolocation.

## Canonical URLs

- Operator geofeed URL: `https://www.daryllswer.com/geofeed`
- GitHub raw CSV target: `https://raw.githubusercontent.com/daryll-swer/ip-geofeed/main/geofeed.csv`
- GitHub repo: `https://github.com/daryll-swer/ip-geofeed`

## File Map

- `geofeed.csv`: RFC 8805 geofeed data for IPv4 and IPv6 prefixes.
- `scripts/validate_geofeed.py`: conservative RFC 8805-style CSV syntax validator.
- `scripts/check_authority.py`: APNIC WHOIS geofeed authority and live-route RPKI validator.
- `.github/workflows/validate.yml`: GitHub Actions validation workflow.
- `docs/adr/0001-geofeed-ci.md`: design record for geofeed CI authority and RPKI validation.

## Operational Invariants

- Keep postal-code fields where present.
- `122.99.126.0/23,,,,` is intentional. It represents an anycast or no-fixed-geography prefix and must not be replaced with an HQ, administrative, or cosmetic location unless explicitly approved.
- Empty country, region, city, and postal fields are allowed only when intentionally representing no precise geolocation.
- Do not add duplicate identical-prefix geofeed rows.
- Do not treat a non-live BGP prefix as invalid solely because it is present in `geofeed.csv`.
- RPKI validation applies to live AS149794-originated BGP prefixes, not every APNIC-held or geofeed-listed prefix.
- Live routed prefixes are discovered from RIPEstat `bgp-state`, filtered where the AS path terminates in AS149794.
- Do not replace RIPEstat `bgp-state` with `announced-prefixes`.
- Do not add secrets, tokens, private keys, credentials, cookies, or internal-only material to this repository.

## Validation

Run these checks before submitting changes:

```bash
python3 scripts/validate_geofeed.py geofeed.csv
python3 scripts/check_authority.py --geofeed geofeed.csv --expected-geofeed https://www.daryllswer.com/geofeed --asn 149794
```

The authority check deliberately separates registry state from routing state:

- every geofeed prefix must be covered by an APNIC `inetnum` or `inet6num` object with the expected `geofeed:` URL;
- geofeed prefixes may be absent from live BGP;
- only prefixes currently observed as announced by AS149794 are checked for RPKI route-origin validity.
