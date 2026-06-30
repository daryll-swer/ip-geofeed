#!/usr/bin/env python3
"""Check APNIC WHOIS geofeed authority and live AS RPKI validity.

Geofeed prefixes are allowed to be absent from the live BGP table. RPKI
route-origin validity is checked only for prefixes currently observed as
announced by the configured AS.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


WHOIS_HOST = "whois.apnic.net"
WHOIS_PORT = 43
RIPESTAT_BASE = "https://stat.ripe.net/data"
USER_AGENT = "AS149794-geofeed-ci/1.0"


@dataclass(frozen=True)
class WhoisObject:
    attrs: dict[str, list[str]]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_geofeed_prefixes(path: Path) -> list[ipaddress._BaseNetwork]:
    prefixes: list[ipaddress._BaseNetwork] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for line_number, row in enumerate(csv.reader(handle), 1):
            if not row:
                continue
            if row[0].startswith("#"):
                continue
            if len(row) != 5:
                fail(f"line {line_number}: expected 5 CSV fields, got {len(row)}")
            try:
                prefixes.append(ipaddress.ip_network(row[0].strip(), strict=True))
            except ValueError as exc:
                fail(f"line {line_number}: invalid prefix {row[0]!r}: {exc}")
    if not prefixes:
        fail("no geofeed prefixes found")
    return prefixes


def whois_query(query: str, retries: int = 3) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with socket.create_connection((WHOIS_HOST, WHOIS_PORT), timeout=20) as sock:
                sock.sendall((query + "\r\n").encode("utf-8"))
                chunks: list[bytes] = []
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", "replace")
        except OSError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    fail(f"APNIC WHOIS query failed for {query!r}: {last_error}")


def parse_whois_objects(text: str) -> list[WhoisObject]:
    objects: list[WhoisObject] = []
    current: dict[str, list[str]] = {}
    last_key: str | None = None

    def flush() -> None:
        nonlocal current, last_key
        if current:
            objects.append(WhoisObject(current))
            current = {}
            last_key = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            flush()
            continue
        if line.startswith("%"):
            continue
        if line[0].isspace() and last_key:
            current[last_key][-1] = current[last_key][-1] + "\n" + line.strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        current.setdefault(key, []).append(value)
        last_key = key
    flush()
    return objects


def object_range(obj: WhoisObject) -> tuple[int, int, int] | None:
    if "inetnum" in obj.attrs:
        value = obj.attrs["inetnum"][0]
        if " - " not in value:
            return None
        start_text, end_text = value.split(" - ", 1)
        start = ipaddress.ip_address(start_text.strip())
        end = ipaddress.ip_address(end_text.strip())
        return int(start), int(end), start.version
    if "inet6num" in obj.attrs:
        network = ipaddress.ip_network(obj.attrs["inet6num"][0], strict=False)
        return int(network.network_address), int(network.broadcast_address), network.version
    return None


def object_covers_prefix(obj: WhoisObject, prefix: ipaddress._BaseNetwork) -> bool:
    rng = object_range(obj)
    if not rng:
        return False
    start, end, version = rng
    return (
        version == prefix.version
        and start <= int(prefix.network_address)
        and int(prefix.broadcast_address) <= end
    )


def check_apnic_geofeed(prefixes: list[ipaddress._BaseNetwork], expected_geofeed: str) -> None:
    print("Checking APNIC WHOIS geofeed references...")
    failures: list[str] = []
    for prefix in prefixes:
        text = whois_query(f"-r {prefix.network_address}")
        objects = parse_whois_objects(text)
        covering = [obj for obj in objects if object_covers_prefix(obj, prefix)]
        if not covering:
            failures.append(f"{prefix}: no covering APNIC inetnum/inet6num object found")
            continue

        with_expected = [
            obj
            for obj in covering
            if expected_geofeed in [value.strip() for value in obj.attrs.get("geofeed", [])]
        ]
        if not with_expected:
            found = sorted(
                {
                    value.strip()
                    for obj in covering
                    for value in obj.attrs.get("geofeed", [])
                }
            )
            failures.append(
                f"{prefix}: covering APNIC object lacks geofeed {expected_geofeed!r}; "
                f"found {found or 'none'}"
            )
            continue
        print(f"OK: {prefix} is covered by APNIC WHOIS geofeed {expected_geofeed}")

    if failures:
        fail("\n".join(failures))


def fetch_json(url: str, retries: int = 3) -> dict:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    fail(f"HTTP JSON fetch failed for {url}: {last_error}")


def get_live_origin_prefixes(asn: int) -> list[ipaddress._BaseNetwork]:
    url = f"{RIPESTAT_BASE}/bgp-state/data.json?resource=AS{asn}"
    payload = fetch_json(url)
    raw_routes = payload.get("data", {}).get("bgp_state", [])
    raw_prefixes = [
        route["target_prefix"]
        for route in raw_routes
        if route.get("path") and route["path"][-1] == asn and route.get("target_prefix")
    ]
    prefixes = sorted(
        {ipaddress.ip_network(prefix, strict=True) for prefix in raw_prefixes},
        key=lambda net: (net.version, int(net.network_address), net.prefixlen),
    )
    if not prefixes:
        fail(f"RIPEstat bgp-state returned no live origin prefixes for AS{asn}")
    return prefixes


def check_rpki(asn: int) -> None:
    print(f"Checking RPKI validity for live BGP origin prefixes from AS{asn}...")
    failures: list[str] = []
    prefixes = get_live_origin_prefixes(asn)
    for prefix in prefixes:
        encoded_prefix = urllib.parse.quote(str(prefix), safe="")
        url = (
            f"{RIPESTAT_BASE}/rpki-validation/data.json"
            f"?resource=AS{asn}&prefix={encoded_prefix}"
        )
        payload = fetch_json(url)
        data = payload.get("data", {})
        status = data.get("status")
        roas = data.get("validating_roas", [])
        if status != "valid":
            failures.append(f"{prefix}: RPKI status is {status!r}; validating_roas={roas!r}")
            continue
        print(f"OK: {prefix} is RPKI valid for AS{asn}")

    if failures:
        fail("\n".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check geofeed APNIC authority and RPKI validity."
    )
    parser.add_argument("--geofeed", default="geofeed.csv")
    parser.add_argument("--expected-geofeed", required=True)
    parser.add_argument("--asn", type=int, required=True)
    args = parser.parse_args()

    prefixes = load_geofeed_prefixes(Path(args.geofeed))
    check_apnic_geofeed(prefixes, args.expected_geofeed)
    check_rpki(args.asn)
    print("OK: APNIC geofeed authority and RPKI checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
