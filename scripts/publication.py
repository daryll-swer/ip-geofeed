"""Poll only selected managed URLs, preserving decoded HTTP body bytes."""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Callable

from audit import Discovery
from feed import BODY_LIMIT, InputError, parse_feed
from report import Report
from transport import Deadline, FetchError, Response, Transport

WINDOW = 2 * 60 * 60
DISCOVERY_REFRESH_RESERVE = 10 * 60
CURRENCY_INTERVAL = 120
BACKOFF_CAP = 15 * 60
CACHE_BODY_LIMIT = BODY_LIMIT + (4 * 1024 * 1024)


def cache_delay(response: Response, wall: float) -> int:
    control = response.headers.get("cache-control", "").lower()
    if re.search(r"(?:^|,)\s*(?:no-cache|no-store)(?:[\s,=]|$)", control):
        return 0
    age = response.headers.get("age", "")
    age = int(age) if re.fullmatch(r"[0-9]{1,9}", age) else 0
    for key in ("s-maxage", "max-age"):
        match = re.search(r'(?:^|,)\s*' + key + r'\s*=\s*"?([0-9]{1,9})"?(?:\s*,|\s*$)', control)
        if match:
            return min(BACKOFF_CAP, max(0, int(match[1]) - age))
    try:
        expires = parsedate_to_datetime(response.headers.get("expires", "")).timestamp()
        return max(0, min(BACKOFF_CAP, int(expires - wall)))
    except (OSError, OverflowError, TypeError, ValueError):
        return 0


@dataclass
class PollResult:
    outcome: str
    code: str = ""
    cache_delay: int = 0


def verify_publication(expected: bytes, discovery: Callable[[Deadline, Report], Discovery],
                       current: Callable[[Deadline], bool], transport: Transport,
                       deadline: Deadline, report: Report) -> None:
    stage = "publication"
    responses: OrderedDict[str, Response] = OrderedDict()
    cached_size = 0
    results: dict[str, PollResult] = {}
    refresh_at = deadline.end - min(DISCOVERY_REFRESH_RESERVE, (deadline.end - deadline.clock.now()) / 4)
    refreshed = False

    def guard() -> bool:
        try:
            deadline.remaining()
            if not current(deadline):
                report.add("currency", "superseded", "main-revision-superseded")
                return False
            deadline.remaining()
        except FetchError as exc:
            report.add("currency", "incomplete", exc.code)
            return False
        report.done("currency")
        return True

    def discover() -> set[str]:
        fresh = Report("publication", report.revision)
        try:
            selected = discovery(deadline, fresh)
            deadline.remaining()
        except FetchError as exc:
            fresh.add("authority", "incomplete", exc.code)
            selected = Discovery(())
        report.findings[:] = [row for row in report.findings if row["stage"] != "authority"]
        report.stages["authority"] = "unevaluated"
        for row in fresh.findings:
            # The discovery report already canonicalised and filtered its prefixes.
            report.findings.append(row)
        report.stages["authority"] = fresh.stages["authority"]
        return selected.managed

    if not guard():
        return
    urls = discover()
    backoff = 60
    while True:
        if report.stages["authority"] in {"incomplete", "failure", "unevaluated"}:
            return
        if not urls:
            report.add(stage, "warning", "no-managed-publications")
            return
        if not guard():
            return
        for index, url in enumerate(sorted(urls)):
            if index and not guard():
                return
            if deadline.clock.now() >= deadline.end:
                break
            try:
                result = transport.get(url, deadline, cached=responses.get(url))
                if result.status != 200:
                    results[url] = PollResult("failure", "publication-http-status",
                                              cache_delay(result, deadline.clock.wall()))
                    continue
                if url in responses:
                    cached_size -= len(responses.pop(url).body)
                if "no-store" not in result.headers.get("cache-control", "").lower():
                    responses[url] = result
                    cached_size += len(result.body)
                    while cached_size > CACHE_BODY_LIMIT:
                        _, evicted = responses.popitem(last=False)
                        cached_size -= len(evicted.body)
                delay = cache_delay(result, deadline.clock.wall())
                if result.body == expected:
                    results[url] = PollResult("pass", cache_delay=delay)
                    continue
                try:
                    parse_feed(result.body, own=True, check_budget=deadline.remaining)
                except InputError as exc:
                    outcome = "incomplete" if exc.code.endswith("-limit") else "failure"
                    results[url] = PollResult(outcome, "managed-" + exc.code, delay)
                else:
                    results[url] = PollResult("failure", "publication-byte-mismatch", delay)
                deadline.remaining()
            except FetchError as exc:
                results[url] = PollResult("incomplete", exc.code)
        if all(url in results and results[url].outcome == "pass" for url in urls):
            if guard():
                report.done(stage)
            return
        now = deadline.clock.now()
        if now >= deadline.end:
            break
        if not refreshed and now >= refresh_at:
            urls = discover()
            refreshed = True
            for url in responses.keys() - urls:
                cached_size -= len(responses.pop(url).body)
            results.clear()  # A final mismatch must follow refreshed discovery.
            continue
        delay = max([backoff] + [item.cache_delay for item in results.values()])
        # Leave room for current-head verification before the window closes.
        wake = min(now + delay, deadline.end - min(45, (deadline.end - now) / 2))
        if not refreshed:
            wake = min(wake, refresh_at)
        if refreshed and deadline.end - now <= 60:
            break
        while deadline.clock.now() < wake:
            deadline.clock.sleep(min(CURRENCY_INTERVAL, wake - deadline.clock.now()))
            if not guard():
                return
        backoff = min(BACKOFF_CAP, backoff * 2)

    if not refreshed or not guard():
        report.add(stage, "incomplete", "publication-final-check-unavailable")
        return
    for url in urls:
        result = results.get(url)
        if result and result.outcome != "pass":
            report.add(stage, result.outcome, result.code)
        elif not result:
            report.add(stage, "incomplete", "publication-final-check-unavailable")
    report.done(stage)
