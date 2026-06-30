#!/usr/bin/env python3
"""Validate the repository geofeed CSV."""

from __future__ import annotations

import csv
import ipaddress
import re
import sys
import unicodedata
from pathlib import Path


COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
REGION_RE = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
POSTAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .-]{0,20}$")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate(path: Path) -> None:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        fail("geofeed.csv must not start with a UTF-8 BOM")

    text = raw.decode("utf-8")
    for index, char in enumerate(text):
        category = unicodedata.category(char)
        if category in {"Cf", "Cc"} and char not in "\r\n\t":
            fail(
                "hidden/control character at byte-like index "
                f"{index}: U+{ord(char):04X} {unicodedata.name(char, 'UNKNOWN')}"
            )

    prefixes: set[str] = set()
    for line_number, row in enumerate(csv.reader(text.splitlines()), 1):
        if not row:
            continue
        if row[0].startswith("#"):
            continue
        if len(row) != 5:
            fail(f"line {line_number}: expected 5 fields, got {len(row)}")

        prefix, country, region, city, postal = [field.strip() for field in row]
        if not prefix:
            fail(f"line {line_number}: prefix is required")
        try:
            network = ipaddress.ip_network(prefix, strict=True)
        except ValueError as exc:
            fail(f"line {line_number}: invalid prefix {prefix!r}: {exc}")

        canonical_prefix = str(network)
        if canonical_prefix in prefixes:
            fail(f"line {line_number}: duplicate prefix {canonical_prefix}")
        prefixes.add(canonical_prefix)

        if country and not COUNTRY_RE.fullmatch(country):
            fail(f"line {line_number}: invalid ISO 3166-1 alpha-2 country {country!r}")
        if region and not REGION_RE.fullmatch(region):
            fail(f"line {line_number}: invalid ISO 3166-2 style region {region!r}")
        if region and not country:
            fail(f"line {line_number}: region is set but country is blank")
        if city and not country:
            fail(f"line {line_number}: city is set but country is blank")
        if postal and not country:
            fail(f"line {line_number}: postal code is set but country is blank")
        if postal and not POSTAL_RE.fullmatch(postal):
            fail(f"line {line_number}: invalid postal code syntax {postal!r}")

    if not prefixes:
        fail("no geofeed prefixes found")
    print(f"OK: validated {len(prefixes)} geofeed prefixes")


if __name__ == "__main__":
    validate(Path(sys.argv[1] if len(sys.argv) > 1 else "geofeed.csv"))
