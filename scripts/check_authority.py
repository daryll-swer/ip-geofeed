#!/usr/bin/env python3
"""Audit geofeed authority and live routes, or verify an accepted publication."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from audit import audit, discover
from evidence import Evidence, as_number
from feed import BODY_LIMIT, POLICY_PATH, InputError, Network, load_policy, parse_feed, read_bounded
from github_state import current_main, repository_name
from publication import WINDOW, verify_publication
from report import SHA, Report
from transport import Clock, Deadline, FetchError, Transport

AUDIT_SECONDS = 15 * 60
EXIT = {"pass": 0, "warning": 0, "failure": 1, "incomplete": 2, "superseded": 3}


def accepted_blob(revision: str) -> bytes:
    def query(mode: str) -> bytes:
        return subprocess.run(["git", "cat-file", mode, f"{revision}:geofeed.csv"], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10).stdout

    try:
        if not SHA.fullmatch(revision) or int(query("-s")) > BODY_LIMIT:
            raise InputError("accepted-feed-unavailable")
        return query("blob")
    except (OSError, ValueError, subprocess.SubprocessError):
        raise InputError("accepted-feed-unavailable") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geofeed", type=Path, default=Path("geofeed.csv"))
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--asn", required=True)
    parser.add_argument("--mode", choices=("audit", "publication"), default="audit")
    parser.add_argument("--repository", help="GitHub owner/repository for publication currency")
    parser.add_argument("--revision", help="Accepted commit SHA for publication, optional for audit")
    parser.add_argument("--json-report", type=Path, help="Write the versioned JSON report")
    args = parser.parse_args()
    if args.revision is not None and not SHA.fullmatch(args.revision):
        parser.error("--revision must be a full lowercase commit SHA")
    if args.mode == "publication" and not (args.repository and args.revision):
        parser.error("publication requires --repository and --revision")
    try:
        asn = as_number(args.asn)
        if args.repository:
            repository_name(args.repository)
    except ValueError:
        parser.error("invalid ASN or repository")

    report = Report(args.mode, args.revision)
    clock = Clock()
    deadline = Deadline(clock, clock.now() + (AUDIT_SECONDS if args.mode == "audit" else WINDOW))
    try:
        policy = load_policy(args.policy)
        raw = read_bounded(args.geofeed)
        feed = parse_feed(raw, own=True, check_budget=deadline.remaining)
        if args.mode == "publication" and raw != accepted_blob(args.revision):
            raise InputError("candidate-not-accepted-revision")
        for code, _ in feed.warnings:
            report.add("input", "warning", code)
        report.done("input")
    except OSError:
        report.add("input", "incomplete", "local-file-unavailable")
    except InputError as exc:
        severity = "incomplete" if exc.code.endswith("-limit") else "failure"
        report.add("input", severity, exc.code)
    except FetchError as exc:
        report.add("input", "incomplete", exc.code)
    if report.stages["input"] in {"pass", "warning"}:
        try:
            deadline.remaining()
            transport = Transport(policy.https_ports)
            if args.mode == "audit":
                audit(feed, policy, Evidence(transport, asn), deadline, report)
            else:
                def get_discovery(budget: Deadline, status: Report):
                    evidence = Evidence(transport, asn)
                    observed: tuple[Network, ...] | None = None
                    attempted = False

                    def origins() -> tuple[Network, ...] | None:
                        nonlocal observed, attempted
                        if not attempted:
                            attempted = True
                            try:
                                observed = evidence.observations(budget).prefixes
                            except FetchError:
                                return None
                        return observed

                    return discover(feed, policy, evidence, budget, status, origins)

                verify_publication(raw, get_discovery,
                                   lambda budget: current_main(transport, args.repository,
                                                               args.revision, budget),
                                   transport, deadline, report)
        except OSError:
            report.add("authority", "incomplete", "transport-initialisation-unavailable")
        except FetchError as exc:
            report.add("authority", "incomplete", exc.code)
    document = json.dumps(report.document(), ensure_ascii=True, separators=(",", ":"))
    if args.json_report:
        try:
            args.json_report.write_text(document + "\n", encoding="ascii")
        except OSError:
            print("ERROR: report-file-unavailable", file=sys.stderr)
            return EXIT["incomplete"]
    print(document)
    return EXIT[report.outcome]


if __name__ == "__main__":
    raise SystemExit(main())
