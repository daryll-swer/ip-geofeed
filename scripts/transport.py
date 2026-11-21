"""Bounded HTTPS and APNIC WHOIS without ambient network configuration."""

from __future__ import annotations

import ipaddress
import json
import queue
import re
import socket
import ssl
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass
from typing import Callable

from feed import BODY_LIMIT, hostname, no_duplicate_keys

ATTEMPT_SECONDS = 120
ATTEMPTS = 3
REDIRECTS = 5
HEADER_LIMIT = 65536
BUFFER = 16384
DNS_SECONDS = 12
UA = "AS149794-geofeed-ci/2.0"
WHOIS_HOST = "whois.apnic.net"
GITHUB = "https://api.github.com"
TRANSIENT = {408, 425, 429, 500, 502, 503, 504}
REDIRECT = {301, 302, 303, 307, 308}
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# getaddrinfo cannot be cancelled portably. Never accumulate timed-out workers.
DNS_SLOT = threading.BoundedSemaphore(1)


class FetchError(Exception):
    """Safe diagnostic code with an explicit transient/permanent distinction."""

    def __init__(self, code: str, *, transient: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.transient = transient


@dataclass(frozen=True)
class Clock:
    now: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    wall: Callable[[], float] = time.time


@dataclass(frozen=True)
class Deadline:
    clock: Clock
    end: float

    def remaining(self) -> float:
        seconds = self.end - self.clock.now()
        if seconds <= 0:
            raise FetchError("deadline-exceeded", transient=True)
        return seconds

    def child(self, seconds: float) -> Deadline:
        self.remaining()
        return Deadline(self.clock, min(self.end, self.clock.now() + seconds))

    def pause(self, seconds: float) -> None:
        self.clock.sleep(min(seconds, self.remaining()))
        self.remaining()


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    port: int
    authority: str
    path: str


def public_ip(value: str) -> bool:
    if "%" in value:
        return False
    ip = ipaddress.ip_address(value)
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
        return False
    if ip.version == 4:
        # Python 3.10 predates corrections to several special-purpose ranges.
        return not any(ip in block for block in V4_SPECIAL)
    # Require native public unicast; avoid mapped/translation/tunnel destinations.
    return ip in V6_UNICAST and not any(ip in block for block in V6_SPECIAL)


V4_SPECIAL = tuple(map(ipaddress.ip_network, ("192.0.0.0/24", "192.88.99.0/24")))
V6_UNICAST = ipaddress.ip_network("2000::/3")
V6_SPECIAL = tuple(map(ipaddress.ip_network, ("2001::/23", "2002::/16", "3fff::/20")))


def url_target(url: str, ports: frozenset[tuple[str, int]] = frozenset()) -> Target:
    try:
        if (not isinstance(url, str) or not 0 < len(url) <= 8192
                or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url)
                or "\\" in url):
            raise ValueError
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or "@" in parsed.netloc
                or "%" in parsed.netloc or parsed.netloc.endswith(":")):
            raise ValueError
        port = parsed.port if parsed.port is not None else 443
        host = parsed.hostname
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if "[" in parsed.netloc or "]" in parsed.netloc:
                raise ValueError
            host = hostname(host)
            if "." not in host:
                raise ValueError
            authority = host
        else:
            if not public_ip(host):
                raise FetchError("non-public-address")
            host = str(ip)
            authority = f"[{host}]" if ip.version == 6 else host
        if port != 443:
            if (host, port) not in ports:
                raise FetchError("unapproved-https-port")
            authority += f":{port}"
        path = urllib.parse.quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            path += "?" + urllib.parse.quote(parsed.query, safe="/?%:@!$&'()*+,;=-._~")
        return Target(f"https://{authority}{path}", host, port, authority, path)
    except (UnicodeError, ValueError):
        raise FetchError("unsafe-https-url") from None


Address = tuple[int, tuple]


def resolve(host: str, port: int, deadline: Deadline) -> list[Address]:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not public_ip(host):
            raise FetchError("non-public-address")
        return [(socket.AF_INET, (str(ip), port))] if ip.version == 4 else [
            (socket.AF_INET6, (str(ip), port, 0, 0))]
    dns = deadline.child(DNS_SECONDS)
    if not DNS_SLOT.acquire(blocking=False):
        raise FetchError("dns-resolver-busy", transient=True)
    result: queue.Queue = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            # A fully qualified name prevents DNS search-list suffix expansion.
            answer = socket.getaddrinfo(host + ".", port, socket.AF_UNSPEC,
                                        socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except OSError:
            answer = None
        finally:
            DNS_SLOT.release()
        result.put_nowait(answer)

    thread = threading.Thread(target=lookup, daemon=True)
    try:
        thread.start()
    except RuntimeError:
        DNS_SLOT.release()
        raise FetchError("dns-worker-unavailable", transient=True) from None
    try:
        infos = result.get(timeout=dns.remaining())
    except queue.Empty:
        raise FetchError("dns-timeout", transient=True) from None
    dns.remaining()
    if not infos or len(infos) > 64:
        raise FetchError("dns-no-usable-answer", transient=True)
    endpoints: list[Address] = []
    for family, _, _, _, address in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise FetchError("dns-unsupported-family")
        try:
            ip = ipaddress.ip_address(address[0])
            if (ip.version != (4 if family == socket.AF_INET else 6)
                    or not public_ip(address[0])
                    or (family == socket.AF_INET6 and address[3] != 0)):
                raise FetchError("non-public-address")
        except ValueError:
            raise FetchError("dns-invalid-answer") from None
        # Reconstruct the numeric sockaddr; connect never receives the DNS name.
        endpoint = (family, (str(ip), port) if ip.version == 4 else (str(ip), port, 0, 0))
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    return endpoints


def dial(host: str, port: int, deadline: Deadline, context: ssl.SSLContext | None) -> socket.socket:
    for family, address in resolve(host, port, deadline):
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(min(12, deadline.remaining()))
            sock.connect(address)
            if context is not None:
                sock.settimeout(deadline.remaining())
                sock = context.wrap_socket(sock, server_hostname=host, suppress_ragged_eofs=False)
            deadline.remaining()
            return sock
        except ssl.SSLCertVerificationError:
            sock.close()
            raise FetchError("tls-verification-failed") from None
        except ssl.SSLError:
            sock.close()
            raise FetchError("tls-protocol-error") from None
        except OSError:
            sock.close()
        except FetchError:
            sock.close()
            raise
    deadline.remaining()
    raise FetchError("connect-unavailable", transient=True)


class Reader:
    def __init__(self, sock: socket.socket, deadline: Deadline) -> None:
        self.sock, self.deadline = sock, deadline
        self.buf = bytearray()

    def recv(self) -> bytes:
        self.sock.settimeout(self.deadline.remaining())
        data = self.sock.recv(BUFFER)
        self.deadline.remaining()
        return data

    def line(self, limit: int) -> bytes:
        while True:
            pos = self.buf.find(b"\n")
            if pos >= 0:
                if pos + 1 > limit or pos == 0 or self.buf[pos - 1] != 13:
                    raise FetchError("invalid-http-line")
                line = bytes(self.buf[:pos - 1])
                del self.buf[:pos + 1]
                return line
            if len(self.buf) >= limit:
                raise FetchError("http-line-limit")
            part = self.recv()
            if not part:
                raise FetchError("truncated-response", transient=True)
            self.buf.extend(part)

    def read(self, count: int) -> bytes:
        if not self.buf:
            self.buf.extend(self.recv())
        data = bytes(self.buf[:count])
        del self.buf[:count]
        return data


def headers(reader: Reader) -> dict[str, str]:
    remaining = HEADER_LIMIT
    result: dict[str, str] = {}
    for _ in range(101):
        line = reader.line(min(8192, remaining))
        remaining -= len(line) + 2
        if not line:
            return result
        key, sep, value = line.partition(b":")
        if not sep or not TOKEN.fullmatch(key) or any(b < 32 and b != 9 or b == 127 for b in value):
            raise FetchError("invalid-http-header")
        name, text = key.decode("ascii").lower(), value.strip(b" \t").decode("latin-1")
        if name in result and name in {"location", "transfer-encoding", "content-length",
                                      "content-encoding", "etag", "last-modified"}:
            raise FetchError("ambiguous-http-header")
        result[name] = result[name] + ", " + text if name in result else text
    raise FetchError("http-header-limit")


def read_body(reader: Reader, fields: dict[str, str], limit: int) -> bytes:
    transfer = fields.get("transfer-encoding", "").lower()
    length = fields.get("content-length")
    if ("transfer-encoding" in fields and transfer != "chunked") or (transfer and length is not None):
        raise FetchError("invalid-http-framing")
    if length is not None and not re.fullmatch(r"[0-9]{1,12}", length):
        raise FetchError("invalid-http-framing")
    encoding = fields.get("content-encoding", "identity").lower()
    if encoding not in {"identity", "gzip"}:
        raise FetchError("unsupported-content-encoding")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    output = bytearray()
    transferred = 0
    framing = 0

    def consume(count: int | None) -> None:
        nonlocal transferred
        if count is not None and count > limit - transferred:
            raise FetchError("transferred-body-limit")
        while count is None or count > 0:
            part = reader.read(BUFFER if count is None else min(BUFFER, count))
            if not part:
                if count is not None:
                    raise FetchError("truncated-response", transient=True)
                break
            transferred += len(part)
            if transferred > limit:
                raise FetchError("transferred-body-limit")
            if count is not None:
                count -= len(part)
            try:
                decoded = decoder.decompress(part, limit - len(output) + 1) if decoder else part
            except zlib.error:
                raise FetchError("invalid-gzip") from None
            output.extend(decoded)
            if len(output) > limit:
                raise FetchError("decoded-body-limit")
            if decoder and decoder.unused_data:
                raise FetchError("invalid-gzip")
            reader.deadline.remaining()

    if transfer:
        while True:
            line = reader.line(1024)
            framing += len(line) + 4
            if framing > HEADER_LIMIT:
                raise FetchError("chunk-framing-limit")
            size = line.partition(b";")[0]
            if not re.fullmatch(rb"[0-9a-fA-F]{1,12}", size) or any(not 32 <= b <= 126 for b in line):
                raise FetchError("invalid-http-chunk")
            count = int(size, 16)
            if not count:
                headers(reader)
                break
            consume(count)
            if reader.line(2):
                raise FetchError("invalid-http-chunk")
    else:
        consume(int(length) if length is not None else None)
    if reader.buf:
        raise FetchError("surplus-http-body")
    if decoder and not decoder.eof:
        raise FetchError("truncated-gzip", transient=True)
    reader.deadline.remaining()
    return bytes(output)


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: dict[str, str]
    url: str


def safe_header(value: str) -> bool:
    return bool(re.fullmatch(r"[ -~]{1,1024}", value))


class Transport:
    def __init__(self, ports: frozenset[tuple[str, int]] = frozenset()) -> None:
        self.ports = ports
        # Unlike create_default_context, this never uses SSLKEYLOGFILE.
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_default_certs()

    def _exchange(self, target: Target, deadline: Deadline, limit: int,
                  extra: dict[str, str], method: str = "GET", body: bytes = b"") -> Response:
        request = {"Host": target.authority, "User-Agent": UA, "Connection": "close",
                   "Accept-Encoding": "gzip", **extra}
        if body:
            request.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
        if any(not safe_header(value) for value in request.values()):
            raise FetchError("invalid-request-header")
        message = f"{method} {target.path} HTTP/1.1\r\n"
        message += "".join(f"{key}: {value}\r\n" for key, value in request.items()) + "\r\n"
        try:
            with dial(target.host, target.port, deadline, self.context) as sock:
                sock.settimeout(deadline.remaining())
                sock.sendall(message.encode("ascii") + body)
                reader = Reader(sock, deadline)
                line = reader.line(8192)
                match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9][0-9])(?: [ -~]*)?", line)
                if not match:
                    raise FetchError("invalid-http-status")
                status = int(match[1])
                fields = headers(reader)
                if status in TRANSIENT:
                    raise FetchError("http-transient-status", transient=True)
                response_body = read_body(reader, fields, limit) if status in {200, 201} else b""
                deadline.remaining()
                return Response(status, response_body, fields, target.url)
        except OSError:
            raise FetchError("network-io-unavailable", transient=True) from None

    def _retry(self, operation: Callable[[Deadline], Response | str],
               deadline: Deadline) -> Response | str:
        for attempt in range(ATTEMPTS):
            try:
                return operation(deadline.child(ATTEMPT_SECONDS))
            except FetchError as exc:
                if not exc.transient or attempt == ATTEMPTS - 1:
                    raise
                deadline.pause(2 ** attempt)
        raise AssertionError("unreachable")

    def get(self, url: str, deadline: Deadline, *, limit: int = BODY_LIMIT,
            cached: Response | None = None, fixed: bool = False, fresh: bool = False) -> Response:
        def operation(attempt: Deadline) -> Response:
            current = url
            seen: set[str] = set()
            for hop in range(REDIRECTS + 1):
                target = url_target(current, self.ports)
                if target.url in seen:
                    raise FetchError("redirect-cycle")
                seen.add(target.url)
                conditional = {"Cache-Control": "no-cache"} if fresh else {}
                has_validator = False
                if cached and cached.url == target.url:
                    for name, header in (("etag", "If-None-Match"),
                                         ("last-modified", "If-Modified-Since")):
                        if safe_header(cached.headers.get(name, "")):
                            conditional[header] = cached.headers[name]
                            has_validator = True
                result = self._exchange(target, attempt, limit, conditional)
                if result.status == 304:
                    if not has_validator or cached is None:
                        raise FetchError("unexpected-not-modified")
                    return Response(200, cached.body, {**cached.headers, **result.headers}, result.url)
                if result.status not in REDIRECT:
                    return result
                if fixed or hop == REDIRECTS or not result.headers.get("location"):
                    raise FetchError("redirect-not-allowed")
                location = result.headers["location"]
                if not safe_header(location) or location != location.strip() or "\\" in location:
                    raise FetchError("unsafe-https-url")
                if any(char.isspace() for char in location):
                    raise FetchError("unsafe-https-url")
                current = urllib.parse.urljoin(target.url, location)
            raise AssertionError("unreachable")

        result = self._retry(operation, deadline)
        assert isinstance(result, Response)
        return result

    def whois(self, query: str, deadline: Deadline) -> str:
        if not re.fullmatch(r"[-A-Za-z0-9 .,:/]{1,160}", query):
            raise FetchError("invalid-whois-query")

        def operation(attempt: Deadline) -> str:
            try:
                with dial(WHOIS_HOST, 43, attempt, None) as sock:
                    sock.settimeout(attempt.remaining())
                    sock.sendall((query + "\r\n").encode("ascii"))
                    reader = Reader(sock, attempt)
                    data = bytearray()
                    while True:
                        part = reader.recv()
                        if not part:
                            break
                        data.extend(part)
                        if len(data) > 4 * 1024 * 1024:
                            raise FetchError("whois-body-limit")
                    return data.decode("utf-8", errors="replace")
            except OSError:
                raise FetchError("whois-unavailable", transient=True) from None

        result = self._retry(operation, deadline)
        assert isinstance(result, str)
        return result

    def github_write_api(self, path: str, deadline: Deadline, token: str, *,
                         method: str = "GET", payload: dict | None = None) -> Response:
        # The only authenticated interface is a fixed origin with no redirects or proxy.
        if not path.startswith("/repos/") or "\\" in path or "#" in path or method not in {
                "GET", "POST", "PATCH"}:
            raise FetchError("invalid-github-api-path")
        target = url_target(GITHUB + path)
        if target.host != "api.github.com" or target.port != 443:
            raise FetchError("invalid-github-api-path")
        return self._exchange(target, deadline.child(30), 4 * 1024 * 1024,
                              {"Authorization": "Bearer " + token,
                               "Accept": "application/vnd.github+json",
                               "Cache-Control": "no-cache",
                               "X-GitHub-Api-Version": "2022-11-28"},
                              method, json.dumps(payload).encode() if payload is not None else b"")


def decode_json(response: Response) -> dict:
    if response.status != 200:
        raise FetchError("api-http-status")
    try:
        value = json.loads(response.body, object_pairs_hook=no_duplicate_keys)
        if not isinstance(value, dict):
            raise ValueError
    except (ValueError, RecursionError):
        raise FetchError("malformed-api-response") from None
    return value
