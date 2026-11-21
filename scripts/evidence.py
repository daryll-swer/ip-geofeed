"""Interpret bounded APNIC/RIPEstat responses; never propagate external text."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlencode

from feed import Network, network, net_key
from transport import Deadline, FetchError, Transport, decode_json, url_target

RDAP = "https://rdap.apnic.net"
RIPESTAT = "https://stat.ripe.net/data"
API_LIMIT = 8 * 1024 * 1024
MAX_OBJECTS = 1024
BGP_MAX_AGE = 12 * 3600


def as_number(value: object) -> int:
    if type(value) is int and 0 < value <= 4294967295:
        return value
    if isinstance(value, str):
        name = value.removeprefix("AS")
        if re.fullmatch(r"[0-9]{1,10}", name):
            return as_number(int(name))
    raise ValueError("invalid ASN")


def timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not 19 <= len(value) <= 35 or "T" not in value:
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


@dataclass(frozen=True)
class Span:
    version: int
    first: int
    last: int

    @classmethod
    def of(cls, prefix: Network) -> Span:
        return cls(prefix.version, int(prefix.network_address), int(prefix.broadcast_address))

    @classmethod
    def parse(cls, first: str, last: str) -> Span:
        if "%" in first or "%" in last:
            raise ValueError
        start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
        if start.version != end.version or int(start) > int(end):
            raise ValueError
        return cls(start.version, int(start), int(end))

    def covers(self, other: Span) -> bool:
        return self.version == other.version and self.first <= other.first <= other.last <= self.last

    def overlaps(self, other: Span) -> bool:
        return self.version == other.version and self.first <= other.last and other.first <= self.last

    def blocks(self) -> list[Network]:
        address = ipaddress.IPv4Address if self.version == 4 else ipaddress.IPv6Address
        return list(ipaddress.summarize_address_range(address(self.first), address(self.last)))

    def query(self) -> str:
        blocks = self.blocks()
        if len(blocks) == 1:
            return str(blocks[0])
        return f"{blocks[0].network_address} - {blocks[-1].broadcast_address}"


@dataclass(frozen=True)
class Registration:
    span: Span
    registrant: str | None
    urls: tuple[str, ...]
    updated: datetime | None = None
    missing_media: bool = False


def registrant(value: dict) -> str | None:
    entities = value.get("entities", [])
    if not isinstance(entities, list) or len(entities) > 256:
        raise ValueError
    handles = set()
    for entity in entities:
        roles = entity.get("roles")
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise ValueError
        if "registrant" in roles:
            handle = entity["handle"]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", handle):
                raise ValueError
            handles.add(handle.upper())
    if len(handles) > 1:
        raise FetchError("contradictory-rdap-registrants")
    return next(iter(handles), None)


def parse_rdap(value: dict, query: Network) -> Registration:
    try:
        span = Span.parse(value["startAddress"], value["endAddress"])
        if value["objectClassName"] != "ip network" or not span.covers(Span.of(query)):
            raise ValueError
        links = value.get("links", [])
        if not isinstance(links, list) or len(links) > 128:
            raise ValueError
        urls, missing_media = [], False
        for link in links:
            if link["rel"] != "geofeed":
                continue
            if any(not isinstance(link.get(field), str) or not 0 < len(link[field]) <= 8192
                   for field in ("value", "href")):
                raise ValueError
            if "type" not in link:
                missing_media = True
            elif link["type"] != "application/geofeed+csv":
                raise ValueError
            urls.append(link["href"])
        return Registration(span, registrant(value), tuple(urls), missing_media=missing_media)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise FetchError("malformed-rdap-network") from None


RPSL_KEYS = {"inetnum", "inet6num", "route", "route6", "source", "org", "origin", "geofeed",
             "last-modified", "remarks"}


def rpsl_objects(text: str) -> list[dict[str, list[str]]]:
    current: dict[str, list[str]] = {}
    objects: list[dict[str, list[str]]] = []
    known_empty = False
    previous: str | None = None
    apnic_header = False

    def finish() -> None:
        if current:
            objects.append(current.copy())
            current.clear()
            if len(objects) > MAX_OBJECTS:
                raise FetchError("whois-object-limit")

    for row in text.splitlines():
        if len(row) > 8192:
            raise FetchError("whois-line-limit")
        if row.startswith("%"):
            apnic_header |= bool(re.search(r"\bAPNIC\b", row, re.IGNORECASE))
            if re.match(r"^%\s*ERROR\b", row, re.IGNORECASE):
                if re.match(r"^%\s*ERROR:101:", row, re.IGNORECASE):
                    known_empty = True
                else:
                    raise FetchError("whois-service-error")
            continue
        if not row.strip():
            finish()
            previous = None
        elif row[0].isspace() or row.startswith("+"):
            if previous and previous in current:
                current[previous][-1] += "\n" + row[1:].strip()
                if len(current[previous][-1]) > 8192:
                    raise FetchError("whois-attribute-limit")
        else:
            key, sep, value = row.partition(":")
            if not sep or not re.fullmatch(r"[A-Za-z0-9-]+", key):
                raise FetchError("malformed-whois-response")
            previous = key.lower()
            if previous in RPSL_KEYS:
                current.setdefault(previous, []).append(value.strip())
    finish()
    if known_empty and not objects:
        return []
    if not objects or known_empty or not apnic_header:
        raise FetchError("malformed-whois-response")
    return objects


def scalar(attrs: dict[str, list[str]], key: str) -> str:
    values = attrs[key]
    if len(values) != 1:
        raise ValueError
    return values[0]


def apnic_source(attrs: dict[str, list[str]]) -> bool:
    return scalar(attrs, "source").partition("#")[0].strip() == "APNIC"


def whois_ranges(text: str) -> list[Registration]:
    result: list[Registration] = []
    try:
        for obj in rpsl_objects(text):
            if not ({"inetnum", "inet6num"} & obj.keys()) or not apnic_source(obj):
                continue
            if "inetnum" in obj:
                first, last = re.split(r"\s*-\s*", scalar(obj, "inetnum"))
                span = Span.parse(first, last)
                if span.version != 4 or "inet6num" in obj:
                    raise ValueError
            else:
                span = Span.of(network(scalar(obj, "inet6num")))
                if span.version != 6:
                    raise ValueError
            urls = obj.get("geofeed", [])
            if not urls:
                urls = [match[1] for remark in obj.get("remarks", [])
                        if (match := re.fullmatch(r"geofeed[ \t]+(\S+)", remark, re.IGNORECASE))]
            org = scalar(obj, "org").upper() if "org" in obj else None
            updated = timestamp(scalar(obj, "last-modified")) if "last-modified" in obj else None
            result.append(Registration(span, org, tuple(urls), updated))
    except (KeyError, ValueError):
        raise FetchError("malformed-whois-registration") from None
    return result


@dataclass(frozen=True)
class Observation:
    prefixes: tuple[Network, ...]
    timestamp: str
    collectors: int
    matching_paths: int


@dataclass(frozen=True)
class Vrp:
    prefix: Network
    origin: int
    max_length: int


@dataclass(frozen=True)
class Rpki:
    state: str
    vrps: tuple[Vrp, ...]


class Evidence:
    def __init__(self, transport: Transport, asn: int) -> None:
        self.transport, self.asn = transport, asn
        self.rdap_cache: dict[Network, Registration] = {}
        self.child_cache: dict[Span, list[Registration]] = {}
        self.rpki_cache: dict[Network, Rpki] = {}

    def rdap(self, query: Network, deadline: Deadline) -> Registration:
        if query not in self.rdap_cache:
            response = self.transport.get(f"{RDAP}/ip/{query}", deadline, limit=API_LIMIT, fixed=True)
            self.rdap_cache[query] = parse_rdap(decode_json(response), query)
        return self.rdap_cache[query]

    def as_registrant(self, deadline: Deadline) -> str:
        value = decode_json(self.transport.get(f"{RDAP}/autnum/{self.asn}", deadline,
                                               limit=API_LIMIT, fixed=True))
        try:
            if (value["objectClassName"] != "autnum" or
                    not as_number(value["startAutnum"]) <= self.asn <= as_number(value["endAutnum"])):
                raise ValueError
            identity = registrant(value)
        except (AttributeError, KeyError, TypeError, ValueError):
            raise FetchError("malformed-rdap-autnum") from None
        if identity is None:
            raise FetchError("missing-as-registrant")
        return identity

    def ranges(self, prefix: Network, deadline: Deadline) -> tuple[list[Registration], Registration]:
        rdap = self.rdap(prefix, deadline)
        area = Span.of(prefix)
        kind = "inetnum" if prefix.version == 4 else "inet6num"
        ancestors = whois_ranges(self.transport.whois(f"-L -r -T {kind} {prefix}", deadline))
        if not ancestors or any(not item.span.covers(area) for item in ancestors):
            raise FetchError("missing-whois-coverage")
        envelope = min((reg.span for reg in ancestors), key=lambda span: span.last - span.first)
        if rdap.span != envelope:
            raise FetchError("rdap-whois-range-conflict")
        # Query the whole enclosing registration: a non-CIDR child may cross the row boundary.
        if envelope not in self.child_cache:
            children = whois_ranges(self.transport.whois(
                f"-M -r -T {kind} {envelope.query()}", deadline))
            if any(child.span == envelope or not envelope.covers(child.span) for child in children):
                raise FetchError("whois-child-range-conflict")
            self.child_cache[envelope] = children
        return ancestors + [r for r in self.child_cache[envelope] if r.span.overlaps(area)], rdap

    def corroborate(self, span: Span, deadline: Deadline) -> Registration:
        # RDAP CIDR lookups cover whole CIDRs, not just their first address.
        for block in sorted(span.blocks(), key=lambda item: item.prefixlen)[:32]:
            result = self.rdap(block, deadline)
            if result.span == span:
                return result
            if not span.covers(result.span):
                break
        raise FetchError("rdap-whois-range-conflict")

    def irr_routes(self, prefix: Network, deadline: Deadline) -> set[Network]:
        kind = "route" if prefix.version == 4 else "route6"
        objects = rpsl_objects(self.transport.whois(f"-L -r -T {kind} {prefix}", deadline))
        result = set()
        try:
            for obj in objects:
                if kind not in obj or not apnic_source(obj):
                    continue
                route = network(scalar(obj, kind))
                if route.version != prefix.version or not prefix.subnet_of(route):
                    raise ValueError
                if as_number(scalar(obj, "origin")) == self.asn:
                    result.add(route)
        except (KeyError, ValueError):
            raise FetchError("malformed-whois-route") from None
        return result

    def _ripe(self, endpoint: str, deadline: Deadline, **query: str) -> dict:
        response = self.transport.get(f"{RIPESTAT}/{endpoint}/data.json?{urlencode(query)}",
                                      deadline, limit=API_LIMIT, fixed=True)
        value = decode_json(response)
        try:
            if (value["status"] != "ok" or value["status_code"] != 200
                    or value["data_call_name"] != endpoint or not isinstance(value["data"], dict)
                    or as_number(value["data"]["resource"]) != self.asn):
                raise ValueError
            return value["data"]
        except (KeyError, ValueError):
            raise FetchError("malformed-ripestat-envelope") from None

    def observations(self, deadline: Deadline) -> Observation:
        data = self._ripe("bgp-state", deadline, resource=f"AS{self.asn}")
        try:
            times = [timestamp(data[key]) for key in ("timestamp", "query_time") if key in data]
            if len(set(times)) != 1:
                raise ValueError
            when = times[0]
            routes = data["bgp_state"]
            if (not isinstance(routes, list) or type(data["nr_routes"]) is not int
                    or data["nr_routes"] != len(routes) or len(routes) > 30_000):
                raise ValueError
            prefixes, collectors, paths = set(), set(), 0
            for row in routes:
                deadline.remaining()
                route = network(row["target_prefix"])
                path = row["path"]
                source = row["source_id"]
                if (not isinstance(path, list) or not 0 < len(path) <= 256
                        or not isinstance(source, str)
                        or not re.fullmatch(r"[0-9]{1,3}-[^-]{1,64}", source)):
                    raise ValueError
                collector, peer = source.split("-", 1)
                ipaddress.ip_address(peer)
                collectors.add(int(collector))
                origin = None
                for hop in path:
                    if isinstance(hop, str) and re.fullmatch(r"\{[0-9,]{1,256}\}", hop):
                        for member in hop[1:-1].split(","):
                            as_number(member)
                        origin = None
                    else:
                        origin = as_number(hop)
                if origin == self.asn:
                    prefixes.add(route)
                    paths += 1
        except (KeyError, TypeError, ValueError):
            raise FetchError("malformed-bgp-observation") from None
        age = deadline.clock.wall() - when.timestamp()
        if age > BGP_MAX_AGE or age < -300:
            raise FetchError("stale-bgp-observation")
        return Observation(tuple(sorted(prefixes, key=net_key)), when.isoformat(), len(collectors), paths)

    def rpki_evidence(self, route: Network, deadline: Deadline) -> Rpki:
        if route in self.rpki_cache:
            return self.rpki_cache[route]
        data = self._ripe("rpki-validation", deadline, resource=f"AS{self.asn}", prefix=str(route))
        try:
            state = data["status"]
            roas = data["validating_roas"]
            if (network(data["prefix"]) != route or state not in {"valid", "invalid_asn",
                                                                 "invalid_length", "unknown"}
                    or not isinstance(roas, list) or len(roas) > MAX_OBJECTS):
                raise ValueError
            valid, vrps = False, []
            for roa in roas:
                deadline.remaining()
                block = network(roa["prefix"])
                origin = roa["origin"]
                # AS0 is a valid ROA origin used to deny routing, not a BGP origin.
                origin = 0 if origin in (0, "0", "AS0") else as_number(origin)
                maximum = roa["max_length"]
                if (not Span.of(block).covers(Span.of(route)) or type(maximum) is not int
                        or not block.prefixlen <= maximum <= route.max_prefixlen):
                    raise ValueError
                vrps.append(Vrp(block, origin, maximum))
                valid |= origin == self.asn and route.prefixlen <= maximum
            if (state == "valid") != valid or (state == "unknown") != (not roas):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise FetchError("malformed-rpki-evidence") from None
        result = Rpki("not-found" if state == "unknown" else state.replace("_", "-"), tuple(vrps))
        self.rpki_cache[route] = result
        return result

    def rpki(self, route: Network, deadline: Deadline) -> str:
        return self.rpki_evidence(route, deadline).state


def reference(reg: Registration, transport: Transport) -> str | None:
    urls = {url_target(value, transport.ports).url for value in reg.urls}
    if len(urls) > 1:
        raise FetchError("ambiguous-registry-reference")
    return next(iter(urls), None)
