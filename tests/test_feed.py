import tempfile
import unittest
from pathlib import Path

import support
from feed import InputError, load_policy, network, parse_feed


class FeedTests(unittest.TestCase):
    def test_optional_fields_comments_and_reserved_legacy_blank(self):
        feed = parse_feed(
            "8.8.8.0/24,,sg-05,北\u200d区,0007 # not part of the feed\r\n"
            "8.8.8.1,ZZ\r\n2001:4860:0000::/32,sg,sg-05,\"A,B\",\r\n"
            "8.8.9.1 # omitted fields\r\n".encode(),
            own=True,
        )
        self.assertEqual(feed.rows[network("8.8.8.0/24")], ("", "SG-05", "北\u200d区", "0007 "))
        self.assertEqual(feed.rows[network("8.8.8.1")], ("", "", "", ""))
        self.assertIn(("legacy-blank-country", 2), feed.warnings)
        self.assertIn(("comma-in-locality", 3), feed.warnings)

    def test_extra_fields_ignored_and_unsigned_authenticator_comments(self):
        raw = b"8.8.8.0/24,US,US-CA,Sample,0099,next,extension\r\n# RPKI Signature:\r\n# data\r\n"
        feed = parse_feed(raw, own=True)
        self.assertEqual(feed.rows[network("8.8.8.0/24")], ("US", "US-CA", "Sample", "0099"))
        self.assertIn(("extra-fields-ignored", 1), feed.warnings)

    def test_strict_vs_interoperable_newlines(self):
        raw = b"8.8.8.8,,,,\n"
        self.assertIn(("lf-line-ending", 0), parse_feed(raw, own=False).warnings)
        with self.assertRaisesRegex(InputError, "publication-requires-crlf"):
            parse_feed(raw, own=True)
        with self.assertRaisesRegex(InputError, "bare-cr"):
            parse_feed(b"8.8.8.8,,,,\r", own=False)

    def test_rejects_bad_csv_iso_and_prefixes_without_echoing_input(self):
        cases = (
            (b"8.8.8.8,XK,,,", "unknown-country"),
            (b"8.8.8.8,SG,SG-99,,", "unknown-subdivision"),
            (b"8.8.8.8,SG,US-CA,,", "inconsistent-subdivision"),
            (b"8.8.8.8,US,,bad\"quote,", "invalid-csv"),
            (b"8.8.8.8,US,,\"bad#comment\",", "invalid-csv"),
            (b"8.8.8.9/24,,,,", "invalid-prefix"),
            (b"8.8.8.0/255.255.255.0,,,,", "invalid-prefix"),
            (b"8.8.8.8,,,,\xff", "invalid-utf8"),
            (b"\xef\xbb\xbf8.8.8.8,,,,", "utf8-bom"),
            (b"8.8.8.8,US,,\x00,", "control-character"),
        )
        for raw, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(InputError, reason):
                parse_feed(raw, own=True)

    def test_canonical_duplicates_and_nesting(self):
        with self.assertRaisesRegex(InputError, "duplicate-prefix"):
            parse_feed(b"2001:4860::1\r\n2001:4860:0:0:0:0:0:1/128", own=True)
        with self.assertRaisesRegex(InputError, "duplicate-prefix"):
            parse_feed(b"8.8.8.8\r\n8.8.8.8/32", own=True)
        self.assertEqual(len(parse_feed(b"2001:4860::/32\r\n2001:4860:1::/48", own=True).rows), 2)

    def test_policy_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            path.write_text('{"version":1,"delegations":["8.8.8.0/24"],'
                            '"https_ports":[{"host":"data.example","port":8443}]}')
            self.assertEqual(load_policy(path).https_ports, {("data.example", 8443)})
            for doc in (
                '{"version":1,"version":1,"delegations":[],"https_ports":[]}',
                '{"version":1,"delegations":["8.8.8.0/24","8.8.8.0/25"],"https_ports":[]}',
                '{"version":1,"delegations":[],"https_ports":[],"geofeed_url":"https://example.com"}',
            ):
                path.write_text(doc)
                with self.subTest(doc=doc), self.assertRaisesRegex(InputError, "invalid-policy"):
                    load_policy(path)
