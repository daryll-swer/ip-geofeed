# Geofeed Validation and Publication Hardening

## Scope and State

Status: deployment authorised and in progress. Local implementation and review are complete. Publish through a pull request with the required `validate` check, then verify trusted workflows, exact CRLF publication and tracking-issue behaviour. No protection changes or forced updates are authorised. Geofeed rows, values, postal codes and comments are unchanged; only line endings changed to CRLF.

This approved implementation supersedes the earlier documentation-only task. Its historical validation passed nine geofeed prefixes and six observed origin routes, not the new implementation.

## Approved Design

### Independent Checks

- Keep main as publication source and validate as deterministic required check: local parsing, policy validation and offline tests; external services never gate it.
- Separate non-required live audits on PR/main from publication verification on trusted main runs. Discover feed URLs from APNIC, never configuration. Proposed rows need not already exist in production.
- Compare repository-managed publications byte-for-byte with the accepted revision after HTTP content decoding but before text normalisation. Delegated feeds have separate audits, not byte equality.
- Two-hour convergence window: bounded cache-aware backoff, conditional requests, no cache-busting URL parameters, no auto-edit/rollback/bypass. Cache discovery while polling and refresh before final mismatch findings.
- Superseded runs stop and cannot replace newer issue state. Ordinary audits have a 15-minute total budget; incomplete and superseded results are not passes.

### Authority and Routing

- Check entire prefix coverage, applicable ancestors and child boundaries, not just the first IP. Select most-specific applicable references; support geofeed and legacy RFC remarks precedence. Never fall back to an overridden parent because the selected feed failed.
- Support RFC 9877 RDAP links when available, otherwise APNIC WHOIS with HTTPS RDAP range/registrant corroboration. Report conflicts. Remain unsigned; disclose the plaintext URL-binding limitation.
- Own resources have the same APNIC registrant as AS149794. Missing/contradictory identity is inconclusive. Own space may be unrouted or leased to other ASNs without AS149794 ROAs.
- Third-party space needs authorisation within the actual leased range: validated ROA evidence for AS149794 or an APNIC route/route6 fallback when the supporting route is RPKI NotFound. Never override invalid or unavailable evidence with IRR.
- Accept geographic more-specifics within authorised routing blocks without separate ROAs. A leased IPv4 /24 cannot authorise its parent /23 or sibling /24; equivalent IPv6 /48 containment applies. Check maxLength for supporting/actual routes, not geographic rows as hypothetical announcements.
- Public prefix-scoped delegation policy identifies independent leases without feed URLs. Honour their references, report conflicting explicit local rows, never auto-edit. No current delegations presumed.
- Own space with no applicable reference warns as undiscoverable; a child without a reference can inherit a covering reference.
- Retain RIPEstat bgp-state, not announced-prefixes; filter AS149794 origin, validate response shape/freshness, report observation scope. Valid empty observations warn, RPKI not evaluated.

### Parser and Transport

- One RFC-aware parser: RFC 8805, 9632, 9877; distinguish mandatory errors from recommendations. Handle permitted field omissions, comments, IP forms, Unicode, case handling and nesting; reject canonical duplicates.
- Own publication strictly CRLF; independent LF feeds accepted with warning. Preserve raw publication bytes; prevent Git newline conversion.
- Hash-pin pycountry 26.2.16 (wheel SHA-256 115c4baf7cceaa30f59a4694d79483c9167dbce7a9de4d3d571c5f3ea77c305a); offline ISO membership/consistency, reviewed updates, documented optional/reserved codes.
- Operator review owns physical geography. Show location changes; preserve postal strings and blanks; no geolocation vendor auto-correction.
- HTTPS and TLS/hostname verification on every hop; dynamically discovered public hosts; port 443 default with reviewed exceptions. Reject userinfo and non-public IPv4/IPv6; validate and pin connected addresses; no second unchecked DNS resolution.
- No ambient proxies, cookies or credentials to discovered endpoints. Bound DNS, headers, reads and elapsed time: 20 MiB transferred/decoded body, 120 seconds per attempt, five redirects, three transient-error attempts. Detect redirect cycles; no truncated passes.
- Bound registry/API responses too. Treat external text as untrusted; sanitise report/issue/log content, never expose contact dumps, credentials or private host details.

### Operations and Interfaces

- Preserve the two script entry points, add explicit audit/publication modes, public policy and JSON report output. Outcomes: pass, warning, failure, incomplete, superseded; identify unevaluated stages.
- Weekly GitHub audit cron: 30 6 * * 6 (Saturday 12:00 IST), manual and PR/main triggers. Schedule is best effort.
- Trusted runs maintain one deduplicated issue including warnings, failures and incomplete checks. Update meaningful changes; close only on complete current recovery. Unsigned is informational, not a perpetual warning.
- Only trusted issue publisher gets issue-write permission. No privileged PR candidate execution, no pull_request_target execution of candidate code. Pin Actions to reviewed immutable commits; minimal permissions.

## Ownership and Progress

- Coordinator owns all Markdown documents, architecture, integration review and verification.
- Approved implementation role: implementer-sol, gpt-6.2-sol high. Owns scripts, tests, workflows, public policy, dependency pin, .gitattributes, CSV newline conversion and necessary ignore rules. No recursive delegation/publication.
- [x] Inspect current state and confirm role configuration.
- [x] Implement parser, transport, authority/routing, publication and reports.
- [x] Implement offline tests and least-privileged workflows/issue reporting.
- [x] Update current docs, add the new ADR and cross-check against implementation.
- [x] Independently review and run tests, bounded live checks and privacy/scope checks.

## Acceptance and Residual Limits

Test parser/ISO edges; leased boundaries/owned leases; missing/ambiguous/delegated references; all RPKI outcomes; empty/malformed/stale BGP; SSRF/DNS rebinding/IPv6/redirects; size/time/decompression budgets; CRLF bytes; independent candidate/publication checks; fake-clock two-hour retries, supersession and issue recovery. No real internal-network probes or external writes in tests.

Run local validators, offline tests, git diff --check, byte/data preservation, bounded live smoke checks and privacy scanning. Registry plaintext binding, unsigned authenticity, incomplete BGP visibility and operator geographic truth remain explicit boundaries. Record actual results before completion.

## Verification Results

Verified locally on 2026-11-21:

- `python3 scripts/validate_geofeed.py geofeed.csv`, using the isolated environment: exit 0, nine prefixes and policy valid. Own LF rejection and independent LF acceptance with a warning are covered.
- `python3 -W error -m unittest discover -s tests`, using the isolated environment: 45 tests passed with warnings treated as errors. Coverage includes registry hierarchy, dormant leased-space ROAs, IRR fallback restrictions, empty observations, byte equality, fake-clock convergence, deadlines, redirects, framing, DNS pinning and issue recovery.
- CSV comparison against the base revision confirms unchanged fields, comments and ordering: 414 to 425 bytes, eleven CRLF records. Git attributes disable CSV newline conversion.
- `python3 scripts/check_authority.py --geofeed geofeed.csv --asn 149794`, using the isolated environment: exit 1 solely for `fetched-publication-requires-crlf`. Current production still serves LF. Input, BGP, RPKI and authority stages passed; seven observed prefixes, 23 collectors, 2,341 matching paths. RIPEstat snapshot: `2026-11-21T13:59:48+00:00`. No external service failure was observed.
- CLI help and the issue publisher's no-authorisation refusal were checked, including a standard-library-only invocation. No issue writes were performed.
- Both workflow files parsed as YAML. Workflow trust-boundary tests pass. Python 3.10 grammar checks pass for all 16 source/test modules; runtime tests used Python 3.15.2, not Python 3.10. Dependency consistency check passes.
- The checkout Action pin resolves to the official [v7.0.1 release commit](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1).
- `git diff --check` and a targeted scan for host paths, credential patterns and private operational history pass. Synthetic hostile inputs in tests are intentional; this review does not prove every possible secret is absent.
- Fresh-agent walkthrough: AGENTS locates purpose, code, invariants, commands and troubleshooting; ADR 0002 records decisions and limits; this file records results and the next action. README remains human-first with short recovery links.

## Remaining Limits

- Live publication equality is not expected until an approved commit publishes CRLF. The currently deployed LF feed is a known transition finding, not permission to bypass checks or publish now.
- The full two-hour convergence and issue lifecycle were tested with fake clocks/transports, not by waiting on production or writing issues. Trusted GitHub runner execution, repository protection configuration and notification delivery were not verified or changed.
- Unsigned operation, plaintext WHOIS URL binding, partial BGP visibility and human-supplied geographic truth remain accepted boundaries. RDAP corroboration and route-origin validation do not sign the feed.
- Serialisation and currency checks reduce stale issue updates but cannot make separate GitHub API requests atomic. A current run reconciles the issue after a race.
- The bounded transport supports HTTP/1.1 with identity or a single gzip stream, not every possible HTTP encoding. Unsupported or limit-exceeding responses fail closed. Tests and review are not a formal proof of every network/parser state.

These are known limits and unverified deployment steps, not authorisation for additional work.

## Next Action

Commit the reviewed changes on a publication branch, open a pull request, wait for the required check and merge normally. Verify the resulting main workflows, APNIC-discovered publication bytes and tracking issue; record observed results. Do not inject faults or create artificial production findings to exercise issue transitions.
