#!/usr/bin/env python3
"""Trusted main-only publisher for sanitised audit and publication results."""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Callable
from urllib.parse import urlencode

from feed import network, no_duplicate_keys
from github_state import TRUSTED_EVENTS, current_main, current_run, repository_name
from report import CODE, MAX_FINDINGS, SEVERITY, SHA, STAGES
from transport import Clock, Deadline, FetchError, Transport, public_ip

TITLE = "Geofeed validation findings"
MARKER = "<!-- ip-geofeed-live-audit:v1 -->"
BOT = "github-actions[bot]"


def issue_lines(raw: str, mode: str, revision: str) -> tuple[bool, list[str]]:
    try:
        if not 0 < len(raw) <= 32768:
            raise ValueError
        report = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        if (type(report["version"]) is not int or report["version"] != 1
                or report["mode"] != mode or report["revision"] != revision):
            raise ValueError
        stages, findings = report["stages"], report["findings"]
        if (set(stages) != set(STAGES[mode]) or any(
            value not in SEVERITY or value == "info" for value in stages.values()
        ) or not isinstance(findings, list) or len(findings) > MAX_FINDINGS):
            raise ValueError
        highest = max(stages.values(), key=SEVERITY.__getitem__)
        outcome = (highest if SEVERITY[highest] > 0 else
                   "incomplete" if "unevaluated" in stages.values() else "pass")
        if report["outcome"] != outcome:
            raise ValueError
        if outcome == "superseded":
            return False, []
        lines = [f"- `{mode}/{stage}`: **{status}**" for stage, status in stages.items()
                 if status != "pass"]
        for item in findings:
            if set(item) - {"stage", "severity", "code", "prefix"}:
                raise ValueError
            stage, severity, code = item["stage"], item["severity"], item["code"]
            if stage not in stages or severity not in {"info", "warning", "failure", "incomplete"}:
                raise ValueError
            if not CODE.fullmatch(code) or (severity != "info" and
                                            SEVERITY[severity] > SEVERITY[stages[stage]]):
                raise ValueError
            prefix = ""
            if "prefix" in item:
                parsed = network(item["prefix"])
                if (str(parsed) != item["prefix"] or not public_ip(str(parsed.network_address))
                        or not public_ip(str(parsed.broadcast_address))):
                    raise ValueError
                prefix = f" (`{parsed}`)"
            if severity != "info":
                lines.append(f"- `{mode}/{stage}`: `{code}`{prefix} ({severity})")
        return outcome == "pass", sorted(set(lines))
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return False, [f"- `{mode}`: **incomplete** (missing or invalid report)"]


class Issues:
    def __init__(self, transport: Transport, repository: str, token: str, deadline: Deadline) -> None:
        self.transport, self.token, self.deadline = transport, token, deadline
        self.path = f"/repos/{repository_name(repository)}/issues"

    def find(self) -> dict | None:
        matches = []
        for page in range(1, 11):
            query = urlencode({"state": "all", "creator": BOT, "per_page": 100, "page": page})
            response = self.transport.github_write_api(self.path + "?" + query, self.deadline, self.token)
            try:
                if response.status != 200:
                    raise ValueError
                issues = json.loads(response.body, object_pairs_hook=no_duplicate_keys)
                if not isinstance(issues, list) or len(issues) > 100:
                    raise ValueError
                for issue in issues:
                    body = issue.get("body") or ""
                    if ("pull_request" not in issue and issue["user"]["login"] == BOT
                            and body.startswith(MARKER + "\n")):
                        if type(issue["number"]) is not int or issue["number"] < 1:
                            raise ValueError
                        if issue["state"] not in {"open", "closed"}:
                            raise ValueError
                        matches.append(issue)
            except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
                raise FetchError("issue-search-unavailable") from None
            if len(issues) < 100:
                if len(matches) > 1:
                    raise FetchError("multiple-tracking-issues")
                return matches[0] if matches else None
        raise FetchError("issue-search-limit")

    def write(self, issue: dict | None, payload: dict) -> None:
        response = self.transport.github_write_api(
            self.path if issue is None else f"{self.path}/{issue['number']}", self.deadline, self.token,
            method="POST" if issue is None else "PATCH", payload=payload)
        if response.status != (201 if issue is None else 200):
            raise FetchError("issue-write-unconfirmed")


def update(issues: Issues, current: Callable[[], bool], audit: str,
           publication: str, revision: str) -> str:
    results = [issue_lines(raw, mode, revision)
               for raw, mode in ((audit, "audit"), (publication, "publication"))]
    if any(not complete and not lines for complete, lines in results) or not current():
        return "superseded"
    existing = issues.find()
    if all(complete for complete, _ in results):
        if existing is None or existing["state"] == "closed":
            return "unchanged"
        if not current():
            return "superseded"
        issues.write(existing, {"state": "closed", "state_reason": "completed"})
        return "closed"
    lines = [line for _, findings in results for line in findings]
    body = MARKER + "\n\nCurrent geofeed checks require attention.\n\n" + "\n".join(lines) + "\n"
    if existing and existing["state"] == "open" and existing["body"] == body:
        return "unchanged"
    if not current():
        return "superseded"
    issues.write(existing, {"title": TITLE, "body": body, **({"state": "open"} if existing else {})})
    return "updated" if existing else "opened"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Allow trusted GitHub workflow writes")
    args = parser.parse_args()
    env = os.environ
    if (not args.apply or env.get("GITHUB_ACTIONS") != "true"
            or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("GITHUB_EVENT_NAME") not in TRUSTED_EVENTS):
        print("issue-publisher-not-authorised")
        return 2
    try:
        repository = repository_name(env["GITHUB_REPOSITORY"])
        revision, token = env["GITHUB_SHA"], env["GH_ISSUE_TOKEN"]
        run_id, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
        if not SHA.fullmatch(revision) or not re.fullmatch(r"[A-Za-z0-9_]{1,512}", token):
            raise ValueError
        if min(run_id, attempt) < 1:
            raise ValueError
        clock = Clock()
        deadline = Deadline(clock, clock.now() + 120)
        transport = Transport()
        issues = Issues(transport, repository, token, deadline)
        result = update(issues, lambda: (
            current_run(transport, repository, revision, run_id, attempt, token, deadline)
            and current_main(transport, repository, revision, deadline)
        ), env.get("AUDIT_REPORT", ""), env.get("PUBLICATION_REPORT", ""), revision)
        print(f"issue-{result}")
        return 0
    except (KeyError, OSError, ValueError, FetchError):
        print("issue-publisher-incomplete")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
