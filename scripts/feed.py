"""Pure parsing and policy for repository and independent feeds."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Location = tuple[str, str, str, str]
BODY_LIMIT = 20 * 1024 * 1024
POLICY_PATH = Path(__file__).resolve().parent.parent / "geofeed-policy.json"
CSV_FIELD = re.compile(r'(?:"(?:[^"]|"")*"|[^,"]*)(?=,|$)')


class InputError(ValueError):
    """Public-safe input finding; never interpolate input text."""

    @property
    def code(self) -> str:
        return str(self).rsplit(": ", 1)[-1]


def read_bounded(path: Path, limit: int = BODY_LIMIT) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise InputError("input-size-limit")
    return raw


def network(value: str) -> Network:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("invalid address")
    if "/" in value and not re.fullmatch(r"[0-9]{1,3}", value.rsplit("/", 1)[1]):
        raise ValueError("invalid prefix length")
    return ipaddress.ip_network(value, strict=True)


def net_key(prefix: Network) -> tuple[int, int, int]:
    return prefix.version, int(prefix.network_address), prefix.prefixlen


@dataclass(frozen=True)
class Feed:
    rows: dict[Network, Location]
    warnings: tuple[tuple[str, int], ...]


def parse_feed(raw: bytes, *, own: bool, check_budget: Callable[[], float] | None = None) -> Feed:
    import pycountry

    if len(raw) > BODY_LIMIT:
        raise InputError("input-size-limit")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InputError("utf8-bom")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("invalid-utf8") from None
    without_crlf = raw.replace(b"\r\n", b"")
    if b"\r" in without_crlf:
        raise InputError("bare-cr")
    lf_only = b"\n" in without_crlf
    if own and lf_only:
        raise InputError("publication-requires-crlf")
    rows: dict[Network, Location] = {}
    warnings: list[tuple[str, int]] = []
    for number, physical in enumerate(io.StringIO(content, newline="\n"), 1):
        if check_budget and number % 128 == 1:
            check_budget()
        line = physical.removesuffix("\n").removesuffix("\r")
        value = line.partition("#")[0]
        if not value.strip():
            continue
        if len(value) > 128 * 1024:
            raise InputError(f"line {number}: record-size-limit")
        if any(unicodedata.category(char) == "Cc" for char in value):
            raise InputError(f"line {number}: control-character")
        try:
            # csv.reader accepts stray quotes inside unquoted fields.
            pos = 0
            while pos < len(value):
                field = CSV_FIELD.match(value, pos)
                if field is None:
                    raise csv.Error
                pos = field.end() + 1
            fields = next(csv.reader([value], strict=True))
        except csv.Error:
            raise InputError(f"line {number}: invalid-csv") from None
        if len(fields) < 5:
            warnings.append(("omitted-fields", number))
        elif len(fields) > 5:
            # RFC 8805 requires consumers to ignore future fields, not reject the row.
            warnings.append(("extra-fields-ignored", number))
        fields = (fields + [""] * 5)[:5]
        prefix, country, region, city, postal = fields
        try:
            key = network(prefix.strip())
        except ValueError:
            raise InputError(f"line {number}: invalid-prefix") from None
        if key in rows:
            raise InputError(f"line {number}: duplicate-prefix")
        if len(rows) >= 500_000:
            raise InputError("row-count-limit")
        if prefix != str(key) and key.version == 6 and "/" in prefix:
            warnings.append(("noncanonical-ipv6", number))
        country, region = country.strip(), region.strip()
        if country and not re.fullmatch(r"[A-Za-z]{2}", country):
            raise InputError(f"line {number}: invalid-country")
        if region and not re.fullmatch(r"[A-Za-z]{2}-[A-Za-z0-9]{1,3}", region):
            raise InputError(f"line {number}: invalid-subdivision")
        country, region = country.upper(), region.upper()
        if country == "ZZ" and not (region or city or postal):
            warnings.append(("legacy-blank-country", number))
            country = ""
        elif country and pycountry.countries.get(alpha_2=country) is None:
            raise InputError(f"line {number}: unknown-country")
        if region and pycountry.subdivisions.get(code=region) is None:
            raise InputError(f"line {number}: unknown-subdivision")
        if country and region and not region.startswith(country + "-"):
            raise InputError(f"line {number}: inconsistent-subdivision")
        if "," in city or "," in postal:
            warnings.append(("comma-in-locality", number))
        rows[key] = (country, region, city, postal)
    if lf_only:
        warnings.insert(0, ("lf-line-ending", 0))
    if not rows:
        raise InputError("empty-feed")
    if check_budget:
        check_budget()
    return Feed(rows, tuple(warnings))


@dataclass(frozen=True)
class Policy:
    delegations: tuple[Network, ...]
    https_ports: frozenset[tuple[str, int]]


DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def hostname(value: str) -> str:
    name = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(name) > 253 or any(not DNS_LABEL.fullmatch(part) for part in name.split(".")):
        raise ValueError("invalid dns name")
    return name


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_policy(path: Path) -> Policy:
    try:
        doc = json.loads(read_bounded(path, 65536), object_pairs_hook=no_duplicate_keys)
        if (set(doc) != {"version", "delegations", "https_ports"}
                or type(doc["version"]) is not int or doc["version"] != 1):
            raise ValueError
        if any(not isinstance(doc[key], list) or len(doc[key]) > 128
               for key in ("delegations", "https_ports")):
            raise ValueError
        delegations: list[Network] = []
        for item in doc["delegations"]:
            prefix = network(item)
            if str(prefix) != item or any(prefix.overlaps(old) for old in delegations
                                          if prefix.version == old.version):
                raise ValueError
            delegations.append(prefix)
        ports: set[tuple[str, int]] = set()
        for item in doc["https_ports"]:
            if set(item) != {"host", "port"}:
                raise ValueError
            host, port = item["host"], item["port"]
            if (host != hostname(host) or "." not in host or type(port) is not int
                    or not 1 <= port <= 65535 or port == 443 or (host, port) in ports):
                raise ValueError
            ports.add((host, port))
    except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise InputError("invalid-policy") from None
    return Policy(tuple(delegations), frozenset(ports))
