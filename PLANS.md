# Geofeed Validation and Publication Hardening

## Scope and State

Status: deployed and verified. Implementation and its token-compatibility correction were published through protected pull requests with the required `validate` check. Trusted workflows, exact CRLF publication and healthy tracking-issue behaviour passed. No repository protections were changed or bypassed. Geofeed rows, values, postal codes and comments are unchanged; only line endings changed to CRLF.

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
- [x] Publish through protected pull requests and verify production workflows, CRLF bytes and healthy issue behaviour.

## Acceptance and Residual Limits

Test parser/ISO edges; leased boundaries/owned leases; missing/ambiguous/delegated references; all RPKI outcomes; empty/malformed/stale BGP; SSRF/DNS rebinding/IPv6/redirects; size/time/decompression budgets; CRLF bytes; independent candidate/publication checks; fake-clock two-hour retries, supersession and issue recovery. No real internal-network probes or external writes in tests.

Run local validators, offline tests, git diff --check, byte/data preservation, bounded live smoke checks and privacy scanning. Registry plaintext binding, unsigned authenticity, incomplete BGP visibility and operator geographic truth remain explicit boundaries. Record actual results before completion.

## Verification Results

Verified locally on 2026-11-21:

- `python3 scripts/validate_geofeed.py geofeed.csv`, using the isolated environment: exit 0, nine prefixes and policy valid. Own LF rejection and independent LF acceptance with a warning are covered.
- `python3 -W error -m unittest discover -s tests`, using the isolated environment: 50 tests passed with warnings treated as errors. Coverage includes registry hierarchy, dormant leased-space ROAs, IRR fallback restrictions, empty observations, byte equality, fake-clock convergence, deadlines, redirects, framing, DNS pinning, opaque credential handling and issue recovery.
- CSV comparison against the base revision confirms unchanged fields, comments and ordering: 414 to 425 bytes, eleven CRLF records. Git attributes disable CSV newline conversion.
- Before deployment, the documented live audit exited 1 solely for the then-published LF file. This transition finding is resolved; the production checks below passed after CRLF publication.
- CLI help and the issue publisher's no-authorisation refusal were checked, including a standard-library-only invocation. No issue writes were performed.
- Both workflow files parsed as YAML. Workflow trust-boundary tests pass. Python 3.10 grammar checks pass for all 16 source/test modules; runtime tests used Python 3.15.2, not Python 3.10. Dependency consistency check passes.
- The checkout Action pin resolves to the official [v7.0.1 release commit](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1).
- `git diff --check` and a targeted scan for host paths, credential patterns and private operational history pass. Synthetic hostile inputs in tests are intentional; this review does not prove every possible secret is absent.
- Fresh-agent walkthrough: AGENTS locates purpose, code, invariants, commands and troubleshooting; ADR 0002 records decisions and limits; this file records results and the next action. README remains human-first with short recovery links.

## Remaining Limits

- The full two-hour timeout and issue create/reopen/update/close lifecycle were tested with fake clocks/transports. Production convergence and the healthy no-issue path were observed, but no artificial faults or issue transitions were injected into production.
- Trusted GitHub execution and existing repository protections were verified. Scheduled delivery and personal notification delivery remain unverified; no notification or protection settings were changed.
- Unsigned operation, plaintext WHOIS URL binding, partial BGP visibility and human-supplied geographic truth remain accepted boundaries. RDAP corroboration and route-origin validation do not sign the feed.
- Serialisation and currency checks reduce stale issue updates but cannot make separate GitHub API requests atomic. A current run reconciles the issue after a race.
- The bounded transport supports HTTP/1.1 with identity or a single gzip stream, not every possible HTTP encoding. Unsupported or limit-exceeding responses fail closed. Tests and review are not a formal proof of every network/parser state.

These are known limits and unverified deployment steps, not authorisation for additional work.

## Production Verification

- [PR 1](https://github.com/daryll-swer/ip-geofeed/pull/1) published the implementation. Its first trusted run exposed a token-format compatibility defect in the issue publisher, while audit and publication verification passed.
- [PR 2](https://github.com/daryll-swer/ip-geofeed/pull/2) corrected the defect as `9f1c398ccb9925bded7fb14d7b66f368c5790a33`. Tokens are now opaque, visible-ASCII strings bounded at 4,096 bytes. Whitespace/control rejection, fixed-origin authentication and no redirects are preserved. Synthetic credentials reproduced the old rejection; no real credential was retrieved or logged.
- [Required validation run](https://github.com/daryll-swer/ip-geofeed/actions/runs/44933172821): success, nine prefixes and policy valid, all 50 tests passed.
- [Trusted live and issue run](https://github.com/daryll-swer/ip-geofeed/actions/runs/44933172705): success. Audit and publication outcomes were `pass`; all seven observed routes passed RPKI. RIPEstat snapshot `2026-11-21T15:59:52+00:00`, 23 collectors and 2,347 matching paths.
- The trusted issue job received issue-write permission and returned `issue-unchanged`. The repository had no tracking issues before or after this healthy run. This verifies absence of a spurious issue, not the live failure/recovery lifecycle.
- From the operator-side check, both documented publication endpoints returned HTTP 200 and exactly matched the committed CSV: 425 bytes, eleven CRLF endings and zero bare LF. SHA-256: `2b3a14644b09722d2d2674f3319cc5dd889bb633e86227c47ae63a55b446ab16`. An initially stale CDN view converged without cache-busting parameters.
- Both workflows are active. Required `validate`, strict up-to-date checks, administrator enforcement and disabled force pushes remain unchanged. Live checks remain separate from the required merge check.

## Next Action

No further implementation or deployment work is pending. Use the weekly or manual audit for subsequent evidence, and investigate actual findings without weakening checks. A live fault-injection or issue-lifecycle exercise requires separate scoped approval; it is not an outstanding authorised task.
