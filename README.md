# AS149794 IP Geofeed

This repository publishes the RFC 8805 geofeed for AS149794.

Stable raw URL:

```text
https://raw.githubusercontent.com/daryll-swer/ip-geofeed/main/geofeed.csv
```

Validation:

```bash
python3 scripts/validate_geofeed.py geofeed.csv
python3 scripts/check_authority.py --geofeed geofeed.csv --expected-geofeed https://www.daryllswer.com/geofeed --asn 149794
```

The authority check deliberately separates registry and routing state:

- every geofeed prefix must be covered by an APNIC `inetnum` or `inet6num` object with the expected `geofeed:` URL;
- geofeed prefixes may be unannounced in live BGP;
- only prefixes currently observed as announced by AS149794 are checked for RPKI route-origin validity.
