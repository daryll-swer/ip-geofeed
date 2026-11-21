# ADR 0002: Independent validation and publication verification

Date: 2026-11-21

Status: Accepted; implementation and validation tracked in [PLANS.md](../../PLANS.md).

## Context

[ADR 0001](0001-geofeed-ci.md) required every proposed prefix to appear in an already published feed. A new prefix could therefore fail pre-merge validation until the very change awaiting approval was published. Comparing only prefix membership also missed stale location fields. Registry registration, routing authorisation, geographic publication and actual BGP observations are different properties and must not be conflated.

This decision replaces that publication dependency and the earlier single blocking live-check design. The previous ADR remains a record of the earlier implementation, not a description of the new checks.

## Decision

### Candidate, Live Audit and Publication

The required `validate` check is deterministic: parse the candidate, validate public policy and run offline tests. No APNIC, RIPEstat or production-feed availability is required for this check. Live audits remain visible but do not gate merging.

Live audits discover geofeed references from APNIC at runtime and fetch the selected publications. They do not require a proposed new row or changed location to exist in production. Fetched data is evidence, not a replacement for the candidate. A broken publication must not prevent a corrective change from being reviewed.

After a trusted main revision is accepted, publication verification compares each repository-managed feed with the exact accepted file bytes. HTTP framing or content decoding is allowed; CSV normalisation, newline conversion, comment stripping and row sorting are not part of equality. Independently delegated feeds are not required to be identical to this file.

Publication may take up to two hours to converge. Poll with bounded backoff and cache-aware requests; cache registry discovery during polling and refresh it before final mismatch findings. Never add cache-busting URL parameters or silently substitute a remembered URL. A run superseded by a newer main revision stops without overwriting newer findings or closing their issue. No automatic rollback, data editing or protection bypass is authorised by an audit failure.

### Registry Authority and Delegation

Check the full address range, including relevant child-assignment boundaries. Select the most-specific applicable reference rather than taking the first matching object or accepting whichever feed passes. Support the RFC-defined `geofeed:` attribute and legacy remarks form with their specified precedence. A missing child reference does not suppress an applicable covering reference. An overridden parent's failed feed must not invalidate a selected child publication.

Use RFC 9877 RDAP geofeed links when available, with WHOIS fallback and HTTPS RDAP corroboration when absent. Conflicting registry references or identity evidence are findings, not permission to choose the convenient answer. URLs remain registry-discovered; a hostname security exception is not a substitute geofeed URL.

Resources with the same APNIC registrant as AS149794 count as owned. They may be unannounced or leased to another ASN without an AS149794 ROA. Unknown or contradictory identity cannot be assumed owned. Owned resources without any applicable geofeed reference remain eligible, with an undiscoverable warning rather than an invented publication endpoint.

Third-party resources require AS149794 routing authorisation within the leased address range. Prefer validated ROA evidence; accept a corresponding APNIC route/route6 object only when the supporting route's RPKI state is NotFound. Invalid or unavailable evidence cannot be bypassed with IRR. The applicable registry geofeed reference remains a separate requirement: routing authorisation does not itself authenticate geographic publication.

A geographic more-specific inside an authorised routing block does not need a separate ROA. For example, authorisation for `192.0.2.0/25` permits geographic rows inside that range, but not `192.0.2.128/25` or `192.0.2.0/24`. An authorised `2001:db8:100::/48` similarly permits contained geographic `/64` rows. ROA maxLength is evaluated for supporting and observed routes, not arbitrary geographic rows treated as hypothetical announcements.

Reviewed prefix-scoped policy records independently published delegations. Honour the selected lessee feed and report conflicting explicit local rows without auto-editing them. Do not infer delegation solely from an unexpected URL, ASN or differing content.

### Parsing and Geographic Truth

Use one shared RFC-aware parser for local and fetched feeds. Distinguish mandatory errors from recommendations and compatibility warnings. Handle optional fields, comments, single addresses, IPv6 representations, case-insensitive codes, Unicode and legitimate nested prefixes; reject canonical duplicate entries. Normalisation for comparisons or lookups never changes the publication bytes.

This repository publishes CRLF and retains all existing comments, data and postal fields. Independent feeds using LF are accepted with a compatibility warning. This is a deliberate interoperability tolerance, not a claim that LF satisfies the publication requirement. Git must not normalise the committed CSV into different bytes.

Pin the ISO-code dependency and hashes; validate country/subdivision membership and consistency offline. Document supported optional/reserved codes rather than treating any two uppercase letters as an assigned country. Dataset updates require review. Geography remains operator-reviewed: neither code membership nor matching published bytes proves physical location. Display changes clearly and preserve intentional no-location entries; do not auto-correct from another geolocation provider.

The initial dataset policy accepts assigned country/subdivision codes case-insensitively. Blank geographic fields remain independent and permitted. Legacy `ZZ` with no locality is interpreted as blank with a warning; it is not a global-anycast location. Other unassigned/reserved codes are not accepted as country membership. Extra future CSV columns are ignored for interpretation as RFC 8805 requires, but remain part of publication byte equality. Input-size and control-character restrictions are explicit safety limits, not geographic validation.

### Routing Observations and Result Semantics

Continue using RIPEstat `bgp-state`, filtered to paths ending in AS149794. Validate response structure and freshness and report observation scope. Do not substitute `announced-prefixes` or claim that one collector service represents every global route.

Timestamp checks validate returned snapshot metadata; they do not establish the health or freshness of every underlying peer session.

Validate actual observed AS149794 routes at their actual lengths. A well-formed empty observation set produces a warning with RPKI not evaluated; it is neither proof of an outage nor a successful RPKI audit. Unavailable, malformed or stale evidence is distinct from invalid routing authorisation.

Results distinguish pass, warning, failure, incomplete and superseded, identifying checks not performed. Non-blocking does not mean suppressing failures. Warnings such as undiscoverable owned prefixes and LF-only independent publications remain visible. Deliberately accepted constraints such as unsigned operation are informational, not perpetual actionable warnings.

### Network and Workflow Boundaries

Treat all registry attributes, URLs, bodies and report text as untrusted. Require HTTPS and certificate/hostname verification on every feed hop, dynamically permit public hosts, and default to port 443 with reviewed exceptions. Reject credentials in URLs and non-public IPv4/IPv6 destinations. Pin connections to validated addresses and repeat checks for redirects; do not re-resolve an unchecked hostname after validation.

Do not inherit ambient proxy credentials, cookies or authorisation headers. Bound DNS resolution, headers, transferred and decoded body size, read duration and whole-operation elapsed time. Defaults are 20 MiB per body, 120 seconds per attempt, five redirects and three transient-error attempts; ordinary audits have a 15-minute budget. A limit-exceeded or truncated result is incomplete, never a successful partial parse. Resource limits are security policy, not additional RFC grammar.

The initial transport supports HTTP/1.1, identity bodies and a single gzip stream. Unsupported encodings and ambiguous framing fail closed rather than being partially interpreted. This bounded interoperability surface is not a claim to implement every HTTP feature.

Run live audits on PR/main changes, by manual request and weekly at Saturday 12:00 IST (`30 6 * * 6` UTC). Scheduled execution is best effort. Only trusted main/scheduled/manual runs may maintain the deduplicated tracking issue. Include warnings, failures and incomplete checks, update meaningful changes, and close only after a complete current recovery. PR runs never receive issue-write credentials; isolate the trusted publisher and sanitise report content.

Workflow concurrency and currency checks immediately before writes reduce stale-result races. The revision/run check and issue update are separate API requests, not an atomic compare-and-swap: a revision can change between them. A later current run reconciles the issue; do not claim the REST sequence eliminates this final race.

## Consequences and Verification

Merging remains possible during registry/API outages and before production contains a proposed row. This deliberately trades a blocking online guarantee for explicit audit visibility and post-publication verification. Publication polling can occupy a runner for up to the convergence window; superseded work must stop promptly.

Unsigned discovery is retained. HTTPS RDAP corroboration does not cryptographically authenticate a URL learned through plaintext WHOIS. Signing, complete global BGP visibility and physical-location proof are not provided. Documenting these boundaries is not a claim of universal RFC certification or exhaustive security proof.

Offline tests must exercise prefix containment, parser differences, authority boundaries, missing/conflicting evidence, unsafe network destinations, bounded retries, byte equality, supersession and issue recovery. Use fake clocks and transports; do not probe internal services or create issues during tests. Record current validation evidence and remaining risks in [PLANS.md](../../PLANS.md). Publication and external activation require separate explicit authorisation.

## References

- [RFC 8805: geofeed format](https://www.rfc-editor.org/rfc/rfc8805.html).
- [RFC 9632: discovery and optional authentication](https://www.rfc-editor.org/rfc/rfc9632.html).
- [RFC 9877: RDAP geofeed extension](https://www.rfc-editor.org/rfc/rfc9877.html).
- [APNIC WHOIS query options](https://www.apnic.net/manage-ip/using-whois/searching/query-options/).
- [APNIC inetnum attributes](https://www.apnic.net/manage-ip/using-whois/guide/inetnum/).
- [RIPEstat BGP State](https://stat.ripe.net/docs/data-api/api-endpoints/bgp-state) and [RPKI Validation](https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation).
- [pycountry data provenance](https://github.com/pycountry/pycountry).
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).
