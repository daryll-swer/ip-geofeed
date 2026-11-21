import json
import os
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from support import Timer, response
from audit import Discovery, Selection
from evidence import Span
from feed import network
from github_state import current_run
from publication import WINDOW, verify_publication
from report import Report
from transport import FetchError, Response
from update_issue import BOT, MARKER, Issues, issue_lines, main, update

REVISION = "a" * 40
URL = "https://managed.example/feed"
NEW_URL = "https://redesign.example/pub"
DELEGATED_URL = "https://delegate.example/feed"
EXPECTED = b"8.8.8.0/24,US,,Example,0001\r\n"
STALE = b"8.8.8.0/24,US,,Example,0002\r\n"


def discover_url(url, report):
    report.done("authority")
    prefix = network("8.8.8.0/24")
    span = Span.of(prefix)
    return Discovery((Selection(prefix, span, span, url, False), Selection(
        prefix, span, span, DELEGATED_URL, True)))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.timer = Timer(WINDOW)
        self.report = Report("publication", REVISION)
        self.report.done("input")
        self.transport = Mock()

    def test_exact_decoded_bytes_not_rows_and_ignore_delegated_feed(self):
        self.transport.get.side_effect = [
            Response(200, EXPECTED.replace(b"\r\n", b"\n"), {"etag": '"old"'}, URL),
            Response(200, EXPECTED, {}, URL),
        ]
        discover = Mock(side_effect=lambda _, report: discover_url(URL, report))
        verify_publication(EXPECTED, discover, lambda _: True, self.transport, self.timer.deadline,
                           self.report)
        self.assertEqual(self.report.outcome, "pass")
        self.assertEqual(self.transport.get.call_count, 2)
        self.assertIsNone(self.transport.get.call_args_list[0].kwargs["cached"])
        self.assertEqual(self.transport.get.call_args_list[1].kwargs["cached"].headers["etag"], '"old"')
        discover.assert_called_once()
        self.assertEqual(self.timer.tick, 60)

    def test_full_bounded_window_refreshes_discovery_before_final_mismatch(self):
        discovery_times = []

        def discover(_, report):
            discovery_times.append(self.timer.tick)
            return discover_url(URL if len(discovery_times) == 1 else NEW_URL, report)

        def fetch(url, _, *, cached):
            return Response(200, STALE, {"cache-control": "max-age=240, public", "age": "30",
                                        "etag": '"stale"'}, url)

        self.transport.get.side_effect = fetch
        verify_publication(EXPECTED, discover, lambda _: True, self.transport, self.timer.deadline,
                           self.report)
        self.assertEqual(self.report.outcome, "failure")
        self.assertIn("publication-byte-mismatch", {item["code"] for item in self.report.findings})
        self.assertEqual(discovery_times, [0.0, WINDOW - 600])
        self.assertGreaterEqual(self.timer.tick, WINDOW - 60)
        self.assertLess(self.timer.tick, WINDOW)
        self.assertTrue(all(call.args[0] in {URL, NEW_URL} for call in self.transport.get.call_args_list))
        first_new = next(call for call in self.transport.get.call_args_list if call.args[0] == NEW_URL)
        self.assertIsNone(first_new.kwargs["cached"])

    def test_whole_window_bounds_initial_discovery_and_final_fetch(self):
        def too_slow(deadline, report):
            self.timer.sleep(WINDOW)
            deadline.remaining()
            return discover_url(URL, report)

        verify_publication(EXPECTED, too_slow, lambda _: True, self.transport,
                           self.timer.deadline, self.report)
        self.assertEqual(self.report.outcome, "incomplete")
        self.transport.get.assert_not_called()
        self.timer = Timer(WINDOW)
        self.report = Report("publication", REVISION)

        def fetch(url, deadline, *, cached):
            if self.timer.tick >= WINDOW - 600:
                self.timer.sleep(deadline.remaining())
                deadline.remaining()
            return Response(200, STALE, {}, url)

        self.transport.get.side_effect = fetch
        verify_publication(EXPECTED, lambda _, report: discover_url(URL, report),
                           lambda deadline: bool(deadline.remaining()), self.transport,
                           self.timer.deadline, self.report)
        self.assertEqual(self.report.outcome, "incomplete")
        self.assertEqual(self.timer.tick, WINDOW)

    def test_superseded_during_poll_cannot_pass(self):
        self.transport.get.return_value = Response(200, STALE, {}, URL)
        verify_publication(EXPECTED, lambda _, report: discover_url(URL, report),
                           lambda _: self.timer.tick < 60, self.transport, self.timer.deadline,
                           self.report)
        self.assertEqual(self.report.outcome, "superseded")
        self.assertEqual(self.transport.get.call_count, 1)

    def test_final_currency_timeout_cannot_turn_exact_bytes_into_pass(self):
        self.transport.get.return_value = Response(200, EXPECTED, {}, URL)
        count = 0

        def current(deadline):
            nonlocal count
            count += 1
            if count == 3:
                self.timer.sleep(deadline.remaining())
            return True

        verify_publication(EXPECTED, lambda _, report: discover_url(URL, report),
                           current, self.transport, self.timer.deadline, self.report)
        self.assertEqual(self.report.outcome, "incomplete")
        self.assertEqual(self.report.stages["publication"], "unevaluated")


def report_json(mode, severity=None):
    report = Report(mode, REVISION)
    for stage in report.stages:
        report.done(stage)
    if severity:
        report.add("input", severity, "input-warning")
    return json.dumps(report.document())


class IssuesTests(unittest.TestCase):
    def setUp(self):
        self.audit = report_json("audit")
        self.publication = report_json("publication")
        self.issues = Mock()
        self.issues.find.return_value = None

    def test_no_apply_is_refused_before_transport(self):
        with patch("sys.argv", ["update_issue.py"]), patch("update_issue.Transport") as network_client, \
                patch("builtins.print"):
            self.assertEqual(main(), 2)
        network_client.assert_not_called()

    def workflow_env(self, token):
        return {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": REVISION, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1",
                "GH_ISSUE_TOKEN": token, "AUDIT_REPORT": self.audit,
                "PUBLICATION_REPORT": self.publication}

    def test_entrypoint_accepts_legacy_and_long_stateless_tokens(self):
        run = {"id": 10, "run_number": 7, "run_attempt": 1, "event": "push",
               "head_branch": "main", "head_sha": REVISION, "created_at": "2026-11-21T16:00:00Z",
               "head_repository": {"full_name": "owner/repo"}}
        for token in ("ghs_" + "a" * 36, "ghs_fixture_" + "a" * 40 + "." + "b" * 426 + "." + "c" * 40):
            replies = [response(run), response({"workflow_runs": [run], "total_count": 1}),
                       response({"ref": "refs/heads/main", "object": {"type": "commit", "sha": REVISION}}),
                       response([])]
            with self.subTest(length=len(token)), patch.dict(os.environ, self.workflow_env(token), clear=True), \
                    patch("sys.argv", ["update_issue.py", "--apply"]), patch("builtins.print") as log, \
                    patch("transport.Transport._exchange", side_effect=replies) as exchange:
                self.assertEqual(main(), 0)
                log.assert_called_once_with("issue-unchanged")
            self.assertEqual(exchange.call_count, 4)
            for call in exchange.call_args_list:
                self.assertEqual((call.args[0].host, call.args[0].port), ("api.github.com", 443))
                self.assertEqual(call.args[4] if len(call.args) > 4 else "GET", "GET")
            self.assertEqual([call.kwargs.get("github_token") for call in exchange.call_args_list],
                             [token, token, None, token])

    def test_entrypoint_token_rejections_are_named_and_do_not_start_transport(self):
        for token, code in (("", "github-token-missing"), ("x" * 4097, "github-token-size-limit"),
                            ("synthetic\r\nInjected: secret", "github-token-unsafe-header"),
                            ("synthetic\u00e9", "github-token-unsafe-header")):
            with self.subTest(code=code), patch.dict(os.environ, self.workflow_env(token), clear=True), \
                    patch("sys.argv", ["update_issue.py", "--apply"]), patch("builtins.print") as log, \
                    patch("update_issue.Transport") as transport:
                self.assertEqual(main(), 2)
                transport.assert_not_called()
                log.assert_called_once_with(f"issue-publisher-incomplete: {code}")

    def test_entrypoint_emits_safe_fetch_error_code(self):
        with patch.dict(os.environ, self.workflow_env("synthetic"), clear=True), \
                patch("sys.argv", ["update_issue.py", "--apply"]), patch("builtins.print") as log, \
                patch("update_issue.current_run", side_effect=FetchError("workflow-currency-unavailable")):
            self.assertEqual(main(), 2)
            log.assert_called_once_with("issue-publisher-incomplete: workflow-currency-unavailable")

    def test_issue_api_only_edits_marked_bot_issue(self):
        marked = {"number": 9, "title": "Previous title", "state": "open",
                  "body": MARKER + "\nprevious", "user": {"login": BOT}}
        another = {**marked, "number": 10, "user": {"login": "human"}}
        transport = Mock()
        transport.github_write_api.side_effect = [response([marked, another]), response(marked)]
        issues = Issues(transport, "owner/repo", "token", Timer().deadline)
        self.assertEqual(update(issues, lambda: True, self.audit, self.publication, REVISION),
                         "closed")
        operation = transport.github_write_api.call_args
        self.assertEqual(operation.args[0], "/repos/owner/repo/issues/9")
        self.assertEqual(operation.kwargs, {"method": "PATCH",
                                            "payload": {"state": "closed", "state_reason": "completed"}})

    def test_issue_opens_updates_only_changes_and_reopens(self):
        warning = report_json("audit", "warning")
        self.assertEqual(update(self.issues, lambda: True, warning, self.publication, REVISION), "opened")
        issue = {"number": 123, "state": "open", "body": self.issues.write.call_args.args[1]["body"]}
        self.assertTrue(issue["body"].startswith(MARKER))
        self.issues.find.return_value = issue
        self.issues.write.reset_mock()
        self.assertEqual(update(self.issues, lambda: True, warning, self.publication, REVISION), "unchanged")
        self.issues.write.assert_not_called()
        issue["state"] = "closed"
        self.assertEqual(update(self.issues, lambda: True, warning, self.publication, REVISION), "updated")
        self.assertEqual(self.issues.write.call_args.args[1]["state"], "open")

    def test_only_complete_current_recovery_could_close(self):
        self.issues.find.return_value = {"number": 123, "state": "open", "body": "previous"}
        self.assertEqual(update(self.issues, lambda: True, self.audit, "", REVISION), "updated")
        self.assertNotEqual(self.issues.write.call_args.args[1].get("state"), "closed")
        self.issues.write.reset_mock()
        current = Mock(side_effect=[True, False])
        self.assertEqual(update(self.issues, current, self.audit, self.publication, REVISION), "superseded")
        self.issues.write.assert_not_called()
        self.assertEqual(update(self.issues, lambda: True, self.audit, self.publication, REVISION), "closed")
        self.assertEqual(self.issues.write.call_args.args[1]["state"], "closed")

    def test_superseded_and_injected_report_never_publish_unsafe_text(self):
        report = Report("publication", REVISION)
        report.add("currency", "superseded", "main-revision-superseded")
        self.assertEqual(update(self.issues, lambda: True, self.audit, json.dumps(report.document()),
                                REVISION), "superseded")
        self.issues.find.assert_not_called()
        tampered = json.loads(report_json("audit", "warning"))
        tampered["findings"][0]["code"] = "@someone https://user:secret@example.org"
        complete, lines = issue_lines(json.dumps(tampered), "audit", REVISION)
        self.assertFalse(complete)
        self.assertNotIn("secret", lines[0])
        self.assertIn("invalid report", lines[0])
        tampered["findings"][0].update({"code": "safe", "prefix": "127.0.0.0/8"})
        self.assertIn("invalid report", issue_lines(json.dumps(tampered), "audit", REVISION)[1][0])

    def test_run_currency_uses_bounded_pagination_without_ordering_assumption(self):
        repository = "owner/repo"
        run = {"id": 10, "run_number": 70, "run_attempt": 2, "event": "schedule",
               "head_branch": "main", "head_sha": REVISION, "created_at": "2026-11-21T16:00:00Z",
               "head_repository": {"full_name": repository}}
        earlier = [dict(run, id=i, run_number=i) for i in range(1, 51)]
        transport = Mock()
        transport.github_write_api.side_effect = [response(run),
                                                  response({"workflow_runs": earlier, "total_count": 51}),
                                                  response({"workflow_runs": [run], "total_count": 51})]
        self.assertTrue(current_run(transport, repository, REVISION, 10, 2, "token", Timer().deadline))
        filter_string = transport.github_write_api.call_args_list[2].args[0]
        self.assertEqual(parse_qs(urlsplit(filter_string).query)["page"], ["2"])
        self.assertIn(">=2026", parse_qs(urlsplit(filter_string).query)["created"][0])
        transport.github_write_api.side_effect = [response(run), response({
            "workflow_runs": [dict(run, id=11, run_number=71), run], "total_count": 2})]
        self.assertFalse(current_run(transport, repository, REVISION, 10, 2, "token", Timer().deadline))
