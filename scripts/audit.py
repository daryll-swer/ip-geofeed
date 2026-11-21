"""Separate registry/reference, leased-space and observed-route decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from evidence import Evidence, Registration, Span, reference
from feed import Feed, InputError, Network, Policy, net_key, parse_feed
from report import Report
from transport import Deadline, FetchError, Transport

MAX_CANDIDATES = 1024
MAX_SELECTIONS = 4096


@dataclass(frozen=True)
class Selection:
    prefix: Network
    cell: Span
    registration: Span
    url: str
    delegated: bool


@dataclass(frozen=True)
class Discovery:
    selected: tuple[Selection, ...]

    @property
    def managed(self) -> set[str]:
        return {choice.url for choice in self.selected if not choice.delegated}


def partition(area: Span, boundaries: list[Span]) -> list[Span]:
    edges = {area.first, area.last + 1}
    for bound in boundaries:
        if area.overlaps(bound):
            edges.update((max(area.first, bound.first), min(area.last, bound.last) + 1))
    sorted_edges = sorted(edges)
    return [Span(area.version, lo, hi - 1) for lo, hi in zip(sorted_edges, sorted_edges[1:])]


def registry_layers(records: list[Registration], cell: Span) -> list[Span]:
    spans = sorted({item.span for item in records if item.span.covers(cell)},
                   key=lambda span: (span.last - span.first, span.first))
    if not spans or any(not larger.covers(smaller) for smaller, larger in zip(spans, spans[1:])):
        raise FetchError("ambiguous-registry-boundaries")
    return spans


def merge_reference(remote: Registration, local: list[Registration], transport: Transport) -> str | None:
    identities = {row.registrant for row in local if row.registrant is not None}
    if len(identities) > 1 or (identities and remote.registrant not in identities):
        raise FetchError("rdap-whois-registrant-conflict")
    remote_ref = reference(remote, transport)
    with_ref = [row for row in local if row.urls]
    local_ref = None
    if with_ref:
        dates = [row.updated for row in with_ref]
        # Without an ordering timestamp, distinct equal-range records are ambiguous.
        newest = (max(dates) if all(date is not None for date in dates) else None)
        applicable = [row for row in with_ref if newest is None or row.updated == newest]
        choices = {reference(row, transport) for row in applicable}
        if len(choices) > 1:
            raise FetchError("ambiguous-registry-reference")
        local_ref = next(iter(choices))
    if remote_ref and local_ref and remote_ref != local_ref:
        raise FetchError("rdap-whois-reference-conflict")
    if local_ref and not remote_ref and not remote.registrant:
        raise FetchError("missing-reference-registrant")
    return remote_ref or local_ref


def supporting_route(prefix: Network, lease: Span, observed: tuple[Network, ...] | None,
                     evidence: Evidence, deadline: Deadline) -> str:
    def eligible(route: Network) -> bool:
        return route.version == prefix.version and prefix.subnet_of(route) and lease.covers(Span.of(route))

    have_invalid = False
    have_unknown = False
    unavailable = False
    routes = {route for route in observed or () if eligible(route)}
    states = {}
    for route in sorted(routes, key=net_key):
        try:
            state = evidence.rpki(route, deadline)
        except FetchError:
            unavailable = True
            states[route] = None
            continue
        states[route] = state
        if state == "valid":
            return "valid"
        have_invalid |= state.startswith("invalid-")
        have_unknown |= state == "not-found"
    # A lookup on a geographic row is only a way to enumerate covering VRPs.
    # Its status is not an announcement judgement for this row.
    try:
        discovery = evidence.rpki_evidence(prefix, deadline)
        blocks = {vrp.prefix for vrp in discovery.vrps if vrp.origin == evidence.asn
                  and eligible(vrp.prefix)}
        for block in sorted(blocks, key=net_key):
            try:
                verified = evidence.rpki_evidence(block, deadline)
            except FetchError:
                unavailable = True
                continue
            if verified.state == "valid" and any(vrp.prefix == block and vrp.origin == evidence.asn
                                                   for vrp in verified.vrps):
                return "valid"
    except FetchError:
        unavailable = True
    irr = {route for route in evidence.irr_routes(prefix, deadline) if eligible(route)}
    irr_not_found = False
    for route in sorted(irr, key=net_key):
        try:
            state = states[route] if route in states else evidence.rpki(route, deadline)
        except FetchError:
            unavailable = True
            continue
        if state == "valid":
            return "valid"
        irr_not_found |= state == "not-found"
        have_invalid |= state is not None and state.startswith("invalid-")
    if irr_not_found and not (unavailable or have_invalid):
        # A registered route cannot cure invalid or unavailable routing evidence.
        return "irr"
    if unavailable or observed is None:
        raise FetchError("lease-evidence-unavailable")
    if have_invalid:
        return "invalid"
    return "no-irr" if have_unknown else "no-route"


def discover(feed: Feed, policy: Policy, evidence: Evidence, deadline: Deadline, report: Report,
             observations: Callable[[], tuple[Network, ...] | None]) -> Discovery:
    stage = "authority"
    report.add(stage, "info", "geofeed-signature-not-verified")
    selected: set[Selection] = set()
    if len(feed.rows) + len(policy.delegations) > MAX_CANDIDATES:
        report.add(stage, "incomplete", "registry-query-count-limit")
        return Discovery(())
    try:
        own_registrant = evidence.as_registrant(deadline)
    except FetchError as exc:
        report.add(stage, "incomplete", exc.code)
        return Discovery(())
    delegated_spans = [Span.of(prefix) for prefix in policy.delegations]
    for prefix in sorted(feed.rows.keys() | set(policy.delegations), key=net_key):
        try:
            deadline.remaining()
            area = Span.of(prefix)
            if prefix in feed.rows and any(span.covers(area) for span in delegated_spans):
                report.add(stage, "failure", "explicit-row-in-independent-delegation", prefix)
            records, primary = evidence.ranges(prefix, deadline)
            by_span: dict[Span, list[Registration]] = {}
            for record in records:
                by_span.setdefault(record.span, []).append(record)
            cache: dict[Span, tuple[Registration, str | None]] = {}
            leases: dict[Span, str] = {}
            for cell in partition(area, list(by_span) + delegated_spans):
                deadline.remaining()
                delegated = next((span for span in delegated_spans if span.covers(cell)), None)
                layers = registry_layers(records, cell)
                for index, span in enumerate(layers):
                    if span not in cache:
                        reg = primary if primary.span == span else evidence.corroborate(span, deadline)
                        ref = merge_reference(reg, by_span[span], evidence.transport)
                        cache[span] = (reg, ref)
                    reg, ref = cache[span]
                    if index == 0:
                        if not reg.registrant:
                            raise FetchError("missing-network-registrant")
                        if not delegated and reg.registrant != own_registrant:
                            if not span.covers(area):
                                report.add(stage, "failure", "lease-does-not-cover-row", prefix)
                                break
                            if span not in leases:
                                leases[span] = supporting_route(prefix, span, observations(),
                                                                evidence, deadline)
                            lease = leases[span]
                            if lease not in {"valid", "irr"}:
                                report.add(stage, "failure", "lease-" + lease, prefix)
                                break
                            if lease == "irr":
                                report.add(stage, "info", "lease-supported-by-apnic-irr", prefix)
                            if ref is None and len(layers) == 1:
                                report.add(stage, "failure", "leased-reference-missing", prefix)
                    if ref is not None:
                        if delegated and not delegated.covers(span):
                            report.add(stage, "failure", "delegation-inherits-external-reference", prefix)
                            break
                        if reg.missing_media:
                            report.add(stage, "warning", "rdap-geofeed-media-type-missing", prefix)
                        if not reg.urls:
                            report.add(stage, "info", "plaintext-whois-url-binding", prefix)
                        if len(selected) >= MAX_SELECTIONS:
                            report.add(stage, "incomplete", "registry-selection-limit")
                            return Discovery(())
                        selected.add(Selection(prefix, cell, span, ref, delegated is not None))
                        break
                else:
                    severity = "failure" if delegated or leases else "warning"
                    code = "delegated-reference-missing" if delegated else (
                        "leased-reference-missing" if leases else "owned-reference-undiscoverable")
                    report.add(stage, severity, code, prefix)
        except FetchError as exc:
            report.add(stage, "incomplete", exc.code, prefix)
            if deadline.clock.now() >= deadline.end:
                break
    managed = {item.url for item in selected if not item.delegated}
    independent = {item.url for item in selected if item.delegated}
    if managed & independent:
        report.add(stage, "failure", "managed-and-delegated-reference-collision")
    report.done(stage)
    # URLs stay inside these objects and never enter logs, report JSON or issue text.
    return Discovery(tuple(sorted(selected, key=lambda x: (net_key(x.prefix), x.cell.first, x.url))))


def audit_feeds(discovery: Discovery, transport: Transport, deadline: Deadline, report: Report) -> None:
    stage = "feeds"
    if not discovery.selected:
        return
    grouped: dict[str, list[Selection]] = {}
    for choice in discovery.selected:
        grouped.setdefault(choice.url, []).append(choice)
    for choices in grouped.values():
        try:
            response = transport.get(choices[0].url, deadline)
            if response.status != 200:
                report.add(stage, "failure", "feed-http-status", choices[0].prefix)
                continue
            parsed = parse_feed(response.body, own=any(not choice.delegated for choice in choices),
                                check_budget=deadline.remaining)
            deadline.remaining()
            for code in sorted({code for code, _ in parsed.warnings}):
                report.add(stage, "warning", code, choices[0].prefix)
            for choice in choices:
                deadline.remaining()
                # Ignore out-of-registration rows; never import candidate membership.
                if choice.delegated:
                    for row in parsed.rows:
                        deadline.remaining()
                        row_span = Span.of(row)
                        if choice.registration.covers(row_span) and choice.cell.overlaps(row_span):
                            break
                    else:
                        report.add(stage, "warning", "delegated-feed-has-no-in-scope-data", choice.prefix)
        except InputError as exc:
            severity = "incomplete" if exc.code.endswith("-limit") else "failure"
            report.add(stage, severity, "fetched-" + exc.code, choices[0].prefix)
        except FetchError as exc:
            report.add(stage, "incomplete", exc.code, choices[0].prefix)
            if deadline.clock.now() >= deadline.end:
                break
    report.done(stage)


def audit(feed: Feed, policy: Policy, evidence: Evidence, deadline: Deadline, report: Report) -> None:
    origins = None
    try:
        observed = evidence.observations(deadline)
        origins = observed.prefixes
        report.observations = {"scope": "ripe-ris-bgp-state", "timestamp": observed.timestamp,
                               "collectors": observed.collectors, "matching_paths": observed.matching_paths,
                               "prefixes": len(origins)}
        if not origins:
            report.add("bgp", "warning", "no-observed-origin-routes")
        report.done("bgp")
    except FetchError as exc:
        report.add("bgp", "incomplete", exc.code)
    if origins:
        for route in origins:
            try:
                state = evidence.rpki(route, deadline)
                if state != "valid":
                    report.add("rpki", "failure", "rpki-" + state, route)
            except FetchError as exc:
                report.add("rpki", "incomplete", exc.code, route)
                if deadline.clock.now() >= deadline.end:
                    break
        report.done("rpki")
    discovered = discover(feed, policy, evidence, deadline, report, lambda: origins)
    audit_feeds(discovered, evidence.transport, deadline, report)
