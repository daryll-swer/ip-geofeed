import random
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

from support import Timer, response
from audit import Discovery, Selection, audit, audit_feeds, discover, merge_reference, partition, supporting_route
from evidence import Evidence, Observation, Registration, Rpki, Span, Vrp, parse_rdap, whois_ranges
from feed import Feed, Policy, network
from report import Report
from transport import FetchError, Response

MANAGED = "https://managed.example/feed"
CHILD = "https://child.example/feed"
NO_POLICY = Policy((), frozenset())


def reg(prefix, urls=(), identity="ORG-OWNER", **kwargs):
    return Registration(Span.of(network(prefix)), identity, urls, **kwargs)


def fake_evidence():
    source = Mock()
    source.asn = 149794
    source.transport.ports = frozenset()
    source.as_registrant.return_value = "ORG-OWNER"
    return source


class RegistryTests(unittest.TestCase):
    def test_rdap_extension_advertisement_not_required_and_types(self):
        prefix = network("8.8.8.0/24")
        base = {
            "objectClassName": "ip network", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "entities": [{"handle": "ORG-OWNER", "roles": ["registrant"]}],
            "links": [{"value": "https://rdap.example/ip/8.8.8.0/24", "rel": "geofeed", "href": MANAGED}],
        }
        reg_apnic = parse_rdap(base, prefix)
        self.assertTrue(reg_apnic.missing_media)
        self.assertEqual(reg_apnic.urls, (MANAGED,))
        for changed in (dict(base, endAddress="8.8.8.127"), dict(base, links=[{"rel": "geofeed"}]),
                        dict(base, links=[None]), dict(base, entities=[None])):
            with self.assertRaises(FetchError):
                parse_rdap(changed, prefix)

    def test_rpsl_attribute_precedence_and_conflicting_rdap(self):
        text = ("% APNIC service\n\ninetnum: 8.8.8.0 - 8.8.8.255\norg: ORG-OWNER\n"
                f"remarks: Geofeed {CHILD}\ngeofeed: {MANAGED}\nsource: APNIC\n")
        local = whois_ranges(text)
        self.assertEqual(local[0].urls, (MANAGED,))
        transport = fake_evidence().transport
        self.assertEqual(merge_reference(reg("8.8.8.0/24"), local, transport), MANAGED)
        self.assertEqual(whois_ranges("% APNIC service\n%ERROR:101: no entries found\n"), [])
        with self.assertRaisesRegex(FetchError, "rdap-whois-reference-conflict"):
            merge_reference(reg("8.8.8.0/24", (CHILD,)), local, transport)
        with self.assertRaisesRegex(FetchError, "ambiguous-registry-reference"):
            merge_reference(reg("8.8.8.0/24", (MANAGED, CHILD)), [], transport)

    def test_real_hierarchy_queries_entire_row_and_covering_envelope(self):
        transport = Mock()
        transport.get.return_value = response({
            "objectClassName": "ip network", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "entities": [{"handle": "ORG-OWNER", "roles": ["registrant"]}],
        })
        transport.whois.side_effect = [
            "% APNIC\n\ninetnum: 8.8.8.0 - 8.8.8.255\nsource: APNIC\n",
            "% APNIC\n\ninetnum: 8.8.8.32 - 8.8.8.159\nsource: APNIC\n",
        ]
        evidence = Evidence(transport, 149794)
        records, remote = evidence.ranges(network("8.8.8.0/25"), Timer().deadline)
        self.assertEqual(len(records), 2)
        self.assertEqual(remote.span, Span.of(network("8.8.8.0/24")))
        self.assertEqual(transport.whois.call_args_list[0].args[0], "-L -r -T inetnum 8.8.8.0/25")
        self.assertEqual(transport.whois.call_args_list[1].args[0], "-M -r -T inetnum 8.8.8.0/24")
        self.assertTrue(transport.get.call_args.args[0].endswith("/ip/8.8.8.0/25"))

    def test_partition_exactly_covers_inclusive_range_and_respects_boundaries(self):
        rng = random.Random(149794)
        area = Span(4, 0, 255)
        for _ in range(100):
            boundaries = [Span(4, *sorted(rng.sample(range(256), 2))) for _ in range(20)]
            outcome = partition(area, boundaries)
            self.assertEqual([addr for part in outcome for addr in range(part.first, part.last + 1)],
                             list(range(256)))
            for part in outcome:
                self.assertTrue(all(not part.overlaps(bound) or bound.covers(part) for bound in boundaries))

    def test_more_specific_reference_wins_even_if_parent_broken(self):
        parent = reg("8.8.8.0/24", ("http://bad.example/feed",))
        child = reg("8.8.8.0/25", (CHILD,))
        evidence = fake_evidence()
        evidence.ranges.return_value = ([child, parent], child)
        report = Report("audit")
        feed = Feed({network("8.8.8.8"): ("US", "", "", "")}, ())
        selection = discover(feed, NO_POLICY, evidence, Timer().deadline, report, lambda: ())
        self.assertEqual(selection.managed, {CHILD})
        evidence.corroborate.assert_not_called()
        self.assertEqual(report.stages["authority"], "pass")

    def test_child_without_reference_inherits_and_owned_need_no_routing(self):
        parent = reg("8.8.8.0/24", (MANAGED,))
        child = reg("8.8.8.0/25")
        evidence = fake_evidence()
        evidence.ranges.return_value = ([child, parent], child)
        evidence.corroborate.return_value = parent
        report = Report("audit")
        feed = Feed({network("8.8.8.8"): ("US", "", "", "")}, ())
        self.assertEqual(discover(feed, NO_POLICY, evidence, Timer().deadline, report,
                                  lambda: None).managed, {MANAGED})
        evidence.rpki.assert_not_called()
        evidence.ranges.return_value = ([child], child)
        report = Report("audit")
        discover(feed, NO_POLICY, evidence, Timer().deadline, report, lambda: None)
        self.assertEqual(report.stages["authority"], "warning")

    def test_delegation_wins_inside_aggregate_and_conflicts_with_explicit_row(self):
        parent, child = reg("8.8.8.0/24", (MANAGED,)), reg("8.8.8.128/25", (CHILD,), "ORG-LESSEE")
        evidence = fake_evidence()
        evidence.ranges.side_effect = lambda prefix, deadline: (
            ([child, parent], parent if prefix.prefixlen == 24 else child))
        evidence.corroborate.return_value = child
        candidates = {network("8.8.8.0/24"): ("US", "", "", "")}
        policy = Policy((network("8.8.8.128/25"),), frozenset())
        report = Report("audit")
        result = discover(Feed(candidates, ()), policy, evidence, Timer().deadline, report, lambda: ())
        self.assertEqual(result.managed, {MANAGED})
        self.assertTrue(any(item.url == CHILD and item.delegated for item in result.selected))
        self.assertEqual(report.stages["authority"], "pass")
        candidates[policy.delegations[0]] = ("", "", "", "")
        report = Report("audit")
        discover(Feed(candidates, ()), policy, evidence, Timer().deadline, report, lambda: ())
        self.assertIn("explicit-row-in-independent-delegation", {f["code"] for f in report.findings})

    def test_unknown_registration_identity_has_no_owned_default(self):
        evidence = fake_evidence()
        item = reg("8.8.8.0/24", (), None)
        evidence.ranges.return_value = ([item], item)
        report = Report("audit")
        discover(Feed({network("8.8.8.8"): ("", "", "", "")}, ()), NO_POLICY,
                 evidence, Timer().deadline, report, lambda: ())
        self.assertEqual(report.stages["authority"], "incomplete")

    def test_eligible_dormant_roa_and_ineligible_parent_or_sibling(self):
        for geo, block, parent, sibling in (
            ("8.8.8.1", "8.8.8.0/24", "8.8.8.0/23", "8.8.9.0/24"),
            ("2001:4860:11::/64", "2001:4860:11::/48", "2001:4860:10::/47", "2001:4860:10::/48"),
        ):
            with self.subTest(geo=geo):
                lease = Span.of(network(block))
                vrp = Vrp(network(block), 149794, network(block).prefixlen)
                evidence = fake_evidence()
                evidence.rpki_evidence.side_effect = lambda candidate, _: (
                    Rpki("valid", (vrp,)) if candidate == vrp.prefix else
                    Rpki("invalid-length", (vrp,)) if lease.covers(Span.of(candidate))
                    else Rpki("not-found", ()))
                evidence.irr_routes.return_value = set()
                self.assertEqual(supporting_route(network(geo), lease, (), evidence, Timer().deadline),
                                 "valid")
                for rejected in (parent, sibling):
                    self.assertEqual(supporting_route(network(rejected), lease, (), evidence,
                                                      Timer().deadline), "no-route")
                self.assertFalse(evidence.rpki.called)

    def test_irr_fallback_only_on_notfound_not_unavailable_or_invalid(self):
        row, route = network("8.8.8.8"), network("8.8.8.0/24")
        lease = Span.of(route)
        evidence = fake_evidence()
        evidence.rpki_evidence.return_value = Rpki("not-found", ())
        evidence.irr_routes.return_value = {route}
        evidence.rpki.return_value = "not-found"
        self.assertEqual(supporting_route(row, lease, (route,), evidence, Timer().deadline), "irr")
        for invalid in ("invalid-asn", "invalid-length"):
            evidence.rpki.return_value = invalid
            self.assertEqual(supporting_route(row, lease, (route,), evidence, Timer().deadline), "invalid")
        evidence.rpki.reset_mock()
        evidence.rpki.side_effect = FetchError("api-unavailable")
        with self.assertRaisesRegex(FetchError, "lease-evidence-unavailable"):
            supporting_route(row, lease, (route,), evidence, Timer().deadline)
        evidence.rpki.assert_called_once()

    def test_audit_does_not_require_candidate_to_exist_and_classifies_lf(self):
        candidate = network("8.8.8.9")
        parent = Span.of(network("8.8.8.0/24"))
        transport = Mock()
        for delegated, ending, wanted in ((False, b"\r\n", "pass"), (False, b"\n", "failure"),
                                          (True, b"\n", "warning")):
            with self.subTest(delegated=delegated, ending=ending):
                transport.get.return_value = Response(200, b"8.8.8.0/24,,,," + ending, {}, MANAGED)
                report = Report("audit")
                audit_feeds(Discovery((Selection(candidate, Span.of(candidate), parent, MANAGED,
                                                 delegated),)), transport, Timer().deadline, report)
                self.assertEqual(report.stages["feeds"], wanted)
                if not delegated and ending == b"\n":
                    self.assertIn("fetched-publication-requires-crlf",
                                  {finding["code"] for finding in report.findings})


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.timer = Timer()
        self.transport = Mock()
        self.evidence = Evidence(self.transport, 149794)
        self.time = datetime.fromtimestamp(self.timer.clock.wall(), timezone.utc).isoformat()

    def ripe(self, endpoint, **data):
        self.transport.get.return_value = response({"status": "ok", "status_code": 200,
                                                    "data_call_name": endpoint,
                                                    "data": {"resource": "149794", **data}})

    def test_fresh_empty_origin_is_warning_and_rpki_unevaluated(self):
        self.ripe("bgp-state", timestamp=self.time, bgp_state=[], nr_routes=0)
        self.assertEqual(self.evidence.observations(self.timer.deadline).prefixes, ())
        evidence = fake_evidence()
        evidence.observations.return_value = Observation((), self.time, 0, 0)
        item = reg("8.8.8.0/24")
        evidence.ranges.return_value = ([item], item)
        report = Report("audit")
        audit(Feed({network("8.8.8.8"): ("", "", "", "")}, ()), NO_POLICY, evidence,
              self.timer.deadline, report)
        self.assertEqual(report.stages["bgp"], "warning")
        self.assertEqual(report.stages["rpki"], "unevaluated")

    def test_bgp_filters_terminal_as_and_validates_freshness_and_entire_path(self):
        valid = {"target_prefix": "8.8.8.0/24", "source_id": "00-8.8.4.4", "path": [210, 149794]}
        foreign = dict(valid, path=[149794, 123])
        self.ripe("bgp-state", timestamp=self.time, bgp_state=[valid, foreign], nr_routes=2)
        result = self.evidence.observations(self.timer.deadline)
        self.assertEqual(result.prefixes, (network("8.8.8.0/24"),))
        self.assertEqual(result.matching_paths, 1)
        for time, route, code in ((self.time, dict(valid, path=[None, 149794]), "malformed-bgp-observation"),
                                  ("2020-01-01T01:01:01Z", valid, "stale-bgp-observation")):
            self.ripe("bgp-state", timestamp=time, bgp_state=[route], nr_routes=1)
            with self.assertRaisesRegex(FetchError, code):
                self.evidence.observations(self.timer.deadline)

    def test_rpki_outcomes_and_max_lengths(self):
        route = network("2001:4860:11::/48")
        for state, roas, expected in (
            ("valid", [("149794", 48)], "valid"),
            ("invalid_asn", [("15169", 48)], "invalid-asn"),
            ("invalid_length", [("149794", 32)], "invalid-length"),
            ("unknown", [], "not-found"),
        ):
            self.evidence.rpki_cache.clear()
            self.ripe("rpki-validation", prefix=str(route), status=state,
                      validating_roas=[{"origin": asn, "prefix": "2001:4860::/32", "max_length": maximum}
                                       for asn, maximum in roas])
            self.assertEqual(self.evidence.rpki(route, self.timer.deadline), expected)
        self.evidence.rpki_cache.clear()
        self.ripe("rpki-validation", prefix=str(route), status="valid", validating_roas=[])
        with self.assertRaisesRegex(FetchError, "malformed-rpki-evidence"):
            self.evidence.rpki(route, self.timer.deadline)
