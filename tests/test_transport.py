import gzip
import socket
import ssl
import threading
import unittest
from unittest.mock import Mock, patch

from support import Timer
from transport import Clock, Deadline, FetchError, Reader, Response, Transport, dial, headers, read_body, resolve, url_target


class Wire:
    def __init__(self, data, timer, delay=0, chunk=16384):
        self.data, self.timer, self.delay, self.chunk = data, timer, delay, chunk

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, count):
        self.timer.sleep(self.delay)
        count = min(count, self.chunk)
        data, self.data = self.data[:count], self.data[count:]
        return data


class TransportTests(unittest.TestCase):
    def test_rejects_credentials_special_ranges_and_ports_before_dial(self):
        for url in (
            "http://example.org/feed", "https://user:secret@example.org/feed", "https://example.org:8443/",
            "https://127.0.0.1/", "https://169.254.169.254/", "https://100.64.0.1/", "https://224.0.0.1/",
            "https://[::ffff:8.8.8.8]/", "https://[fc00::1]/", "https://[fe80::1%25en0]/",
            "https://[2002:7f00:1::]/", "https://[64:ff9b::7f00:1]/", "https://[3fff::1]/",
            "https://[v1.example]/", "https://example.org\\@example.com/",
        ):
            with self.subTest(url=url), self.assertRaises(FetchError):
                url_target(url)
        self.assertEqual(url_target("https://[2606:4700::1111]/").host, "2606:4700::1111")
        self.assertEqual(url_target("https://example.org:8443/", {("example.org", 8443)}).port, 8443)

    def test_rejects_mixed_dns_answers_before_any_connection(self):
        answers = [(socket.AF_INET, 1, 6, "", ("8.8.8.8", 443)),
                   (socket.AF_INET6, 1, 6, "", ("::1", 443, 0, 0))]
        with patch("transport.socket.getaddrinfo", return_value=answers), patch("transport.socket.socket") as sock:
            with self.assertRaisesRegex(FetchError, "non-public-address"):
                dial("example.org", 443, Timer().deadline, None)
            sock.assert_not_called()

    def test_resolution_is_pinned_and_hostname_still_verified(self):
        answers = [(socket.AF_INET6, 1, 6, "", ("2606:4700::1111", 443, 0, 0))]
        ctx = Mock()
        with patch("transport.socket.getaddrinfo", side_effect=[answers, OSError()]) as resolver, \
                patch("transport.socket.socket") as sock:
            self.assertIs(dial("example.org", 443, Timer().deadline, ctx), ctx.wrap_socket.return_value)
            resolver.assert_called_once()
            sock.return_value.connect.assert_called_once_with(("2606:4700::1111", 443, 0, 0))
            ctx.wrap_socket.assert_called_once_with(sock.return_value, server_hostname="example.org",
                                                    suppress_ragged_eofs=False)
        real = Transport().context
        self.assertTrue(real.check_hostname)
        self.assertEqual(real.verify_mode, ssl.CERT_REQUIRED)

    def test_dns_deadline_stops_waiting_for_uncancellable_lookup(self):
        timer = Timer(0.02)
        clock = Clock()
        deadline = Deadline(clock, clock.now() + 0.02)
        release = threading.Event()
        workers = []
        thread = threading.Thread

        def blocked(*_):
            release.wait(1)
            return []

        def capture(*args, **kwargs):
            worker = thread(*args, **kwargs)
            workers.append(worker)
            return worker

        try:
            with patch("transport.socket.getaddrinfo", side_effect=blocked), \
                    patch("transport.threading.Thread", side_effect=capture):
                with self.assertRaisesRegex(FetchError, "dns-timeout"):
                    resolve("example.org", 443, deadline)
                with self.assertRaisesRegex(FetchError, "dns-resolver-busy"):
                    resolve("example.net", 443, timer.deadline)
        finally:
            release.set()
            for worker in workers:
                worker.join(1)
                self.assertFalse(worker.is_alive())

    def test_redirect_validates_every_hop_and_never_forwards_foreign_validators(self):
        client = Transport()
        cached = Response(200, b"cached", {"etag": '"private"'}, "https://example.org/start")
        with patch.object(client, "_exchange", side_effect=[
            Response(302, b"", {"location": "https://another.example/feed"}, cached.url),
            Response(200, b"new", {}, "https://another.example/feed"),
        ]) as request:
            self.assertEqual(client.get(cached.url, Timer().deadline, cached=cached).body, b"new")
            self.assertEqual(request.call_args_list[0].args[3], {"If-None-Match": '"private"'})
            self.assertEqual(request.call_args_list[1].args[3], {})
        for redirect, code in (("https://[::1]/", "non-public-address"), ("/start", "redirect-cycle"),
                               ("http://another.example/feed", "unsafe-https-url")):
            with patch.object(client, "_exchange", return_value=Response(302, b"", {"location": redirect},
                                                                         cached.url)) as request:
                with self.subTest(redirect=redirect), self.assertRaisesRegex(FetchError, code):
                    client.get(cached.url, Timer().deadline)
                request.assert_called_once()

    def test_conditional_hit_and_transient_retry_budget(self):
        client = Transport()
        saved = Response(200, b"\r\n", {"etag": '"seen"'}, "https://example.org/")
        timer = Timer()
        with patch.object(client, "_exchange", side_effect=[
            FetchError("retry", transient=True), FetchError("retry", transient=True),
            Response(304, b"", {}, saved.url),
        ]) as request:
            self.assertEqual(client.get(saved.url, timer.deadline, cached=saved).body, b"\r\n")
            self.assertEqual(request.call_count, 3)
            self.assertEqual(timer.tick, 3)

    def test_five_redirects_allowed_but_no_sixth_hop(self):
        client = Transport()
        for final_status in (200, 302):
            replies = [Response(302, b"", {"location": f"/{i + 1}"}, f"https://example.org/{i}")
                       for i in range(5)]
            replies.append(Response(final_status, b"", {"location": "/6"}, "https://example.org/5"))
            with self.subTest(final=final_status), patch.object(client, "_exchange", side_effect=replies) as send:
                if final_status == 200:
                    self.assertEqual(client.get("https://example.org/0", Timer().deadline).status, 200)
                else:
                    with self.assertRaisesRegex(FetchError, "redirect-not-allowed"):
                        client.get("https://example.org/0", Timer().deadline)
                self.assertEqual(send.call_count, 6)

    def test_tls_verification_or_protocol_failure_never_falls_back_to_cleartext(self):
        for fault, expected in ((ssl.SSLCertVerificationError(), "tls-verification-failed"),
                                (ssl.SSLError(), "tls-protocol-error")):
            with self.subTest(expected=expected), patch("transport.socket.socket") as sock:
                context = Mock()
                context.wrap_socket.side_effect = fault
                with self.assertRaisesRegex(FetchError, expected):
                    dial("8.8.8.8", 443, Timer().deadline, context)
                sock.return_value.close.assert_called_once()
                sock.return_value.sendall.assert_not_called()

    def test_headers_and_body_use_absolute_budget_even_with_progress(self):
        timer = Timer(5)
        reader = Reader(Wire(b"HTTP/1.1 200 OK\r\n", timer, delay=1, chunk=1), timer.deadline)
        with self.assertRaisesRegex(FetchError, "deadline-exceeded"):
            reader.line(8192)
        self.assertEqual(timer.tick, 5)
        timer = Timer(5)
        reader = Reader(Wire(b"abcdefgh", timer, delay=1, chunk=1), timer.deadline)
        with self.assertRaisesRegex(FetchError, "deadline-exceeded"):
            read_body(reader, {"content-length": "8"}, 8)

    def test_framing_and_compression_bounds(self):
        encoded = gzip.compress(b"loc\r\n")
        timer = Timer()
        chunks = f"{len(encoded):x}\r\n".encode() + encoded + b"\r\n0\r\n\r\n"
        self.assertEqual(read_body(Reader(Wire(chunks, timer), timer.deadline),
                                   {"transfer-encoding": "chunked", "content-encoding": "gzip"}, 100),
                         b"loc\r\n")
        cases = [
            (b"3\r\nab", {"transfer-encoding": "chunked"}, 10, "truncated-response"),
            (b"2\r\nab\r\n0\r\n", {"transfer-encoding": "chunked"}, 10, "truncated-response"),
            (b"1\r\na\r\n" * 14000, {"transfer-encoding": "chunked"}, 20000, "chunk-framing-limit"),
            (b"", {"content-length": "128"}, 100, "transferred-body-limit"),
            (encoded[:-5], {"content-encoding": "gzip"}, 100, "truncated-gzip"),
            (gzip.compress(b"a" * 1000), {"content-encoding": "gzip"}, 100, "decoded-body-limit"),
            (b"abcdef", {"content-length": "3"}, 100, "surplus-http-body"),
        ]
        for data, headers, limit, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(FetchError, code):
                read_body(Reader(Wire(data, timer), timer.deadline), headers, limit)

    def test_rejects_duplicate_or_oversized_http_headers(self):
        timer = Timer()
        for raw, code in (
            (b"Content-Length: 10\r\nContent-Length: 9\r\n\r\n", "ambiguous-http-header"),
            (b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", "ambiguous-http-header"),
            (b"x: " + b"a" * 9000 + b"\r\n", "invalid-http-line"),
            ((b"x: " + b"a" * 1000 + b"\r\n") * 80, "http-line-limit|invalid-http-line"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(FetchError, code):
                headers(Reader(Wire(raw, timer), timer.deadline))
        with self.assertRaisesRegex(FetchError, "invalid-http-framing"):
            read_body(Reader(Wire(b"", timer), timer.deadline),
                      {"transfer-encoding": "chunked", "content-length": "10"}, 100)

    def test_authenticated_origin_and_redirect_boundary(self):
        client = Transport()
        with patch.object(client, "_exchange") as request:
            with self.assertRaisesRegex(FetchError, "invalid-github-api-path"):
                client.github_write_api("@host.example", Timer().deadline, "token")
            request.assert_not_called()
