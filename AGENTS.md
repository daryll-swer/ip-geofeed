# AGENTS.md

## Purpose and Recovery

This repository publishes public RFC 8805 geofeed data for AS149794. Treat it as operational network data; preserve correctness over cosmetic geolocation.

Read this file, [PLANS.md](PLANS.md), then [ADR 0002](docs/adr/0002-independent-validation-and-publication.md). Inspect `git status --short --branch`, `git diff` and affected code before editing. Preserve user changes. [ADR 0001](docs/adr/0001-geofeed-ci.md) describes the superseded design, not current validation guarantees.

Keep task progress, actual test results, unresolved risks and the next action in PLANS.md. Keep durable decisions in ADRs. Recorded validation is historical evidence; rerun drift-prone external checks. Do not assume Markdown files load automatically.

## Publication Endpoints

- Operator convenience URL: https://www.daryllswer.com/geofeed
- Raw publication: https://raw.githubusercontent.com/daryll-swer/ip-geofeed/main/geofeed.csv
- Repository: https://github.com/daryll-swer/ip-geofeed

These are descriptive links, not validator inputs or fallback URLs. Discover applicable geofeed references from APNIC at runtime. Geofeed authenticity remains unsigned; HTTPS registration corroboration does not authenticate a URL learned through plaintext WHOIS.

## File Map

- `geofeed.csv`: public IPv4/IPv6 data; preserve CRLF bytes for this publication.
- `scripts/validate_geofeed.py`: deterministic local validation entry point.
- `scripts/check_authority.py`: live audit and publication verification entry point.
- `scripts/feed.py`: shared CSV parsing, ISO checks and public policy validation.
- `scripts/transport.py`: bounded HTTPS/WHOIS, public-address checks and pinned connections.
- `scripts/evidence.py`: APNIC/RIPEstat response interpretation and registration/routing evidence.
- `scripts/audit.py`: ownership, lease containment, reference selection and live audits.
- `scripts/report.py`: public-safe stage outcomes and findings.
- `scripts/publication.py`: bounded cache-aware byte verification and convergence.
- `scripts/github_state.py`: main-revision and workflow-run currency checks.
- `scripts/update_issue.py`: guarded trusted-workflow issue reporting; no local writes without explicit authorisation.
- `geofeed-policy.json`: reviewed prefix delegations and HTTPS-port exceptions, never feed URLs.
- `requirements.txt`: hash-pinned ISO dataset dependency.
- `.gitattributes`: preserves the committed CSV's CRLF bytes.
- `tests/`: offline fixtures, boundary cases and security regression tests.
- `.github/workflows/`: required local validation and separate non-blocking live checks.
- `docs/adr/0002-independent-validation-and-publication.md`: current design, trust boundaries and accepted limitations.
- `PLANS.md`: current implementation state, verification and next action.

## Operational Invariants

- Preserve postal strings, including leading zeroes, and all intentionally blank location fields.
- `122.99.126.0/23,,,,` and `2400:7060::/44,,,,` intentionally specify no fixed geography. Never replace them with administrative, HQ or guessed locations without approval.
- Preserve `122.99.127.0/24,SG,SG-05,Singapore,627753` and `2400:7060:1::/48,SG,SG-05,Singapore,627753` unless explicitly approved to change them.
- Preserve intentional nesting; an aggregate and its more-specific are not duplicate prefixes. Do not fill explicit blanks from the covering row or flatten the feed.
- Canonically identical prefixes are duplicates, even when their textual IPv6 representations differ.
- Geographic data need not be live in BGP. Owned space may be dormant or leased to another ASN.
- Third-party space requires authorisation within the actual leased range. Geographic more-specifics inside it need not be separately route-authorised; never extend approval to a parent or sibling outside the authorised range.
- Actual AS149794-originated routes are checked at their real prefix lengths. Keep RIPEstat `bgp-state`; do not substitute `announced-prefixes`.
- Honour explicit prefix-scoped delegations and the most-specific applicable registry reference. Do not silently treat any unexpected feed as an approved delegation.
- Own publication uses CRLF; independently published LF feeds remain interoperable with a warning. Byte comparison never normalises content.
- No secrets, credentials, cookies, private keys, contact dumps, internal-only data, host paths or session material belong in the repository or reports.

## Validation Boundaries

The required `validate` check is local and deterministic. External checks are separate and non-blocking; never restore the dependency requiring proposed rows to exist in production before merge.

A live audit checks discovered authority, selected feeds and observed routes. Publication verification checks managed feeds against accepted raw bytes, allowing up to two hours for convergence. Delegated publications are not byte-compared with this repository. Superseded runs cannot replace newer findings.

Missing evidence is not a pass. Report warnings, failures, incomplete checks and supersession distinctly. A valid empty BGP response warns and records RPKI not evaluated. Owned space lacking all applicable geofeed references warns as undiscoverable; do not invent a URL.

Geographic truth remains operator-reviewed. Code membership and successful publication do not prove physical location. Signed-geofeed authentication and complete global BGP visibility are not provided.

## Troubleshooting and Scope

1. Validate the local file and policy, then run offline tests. Separate mandatory format errors from interoperability warnings. Preserve data while correcting confirmed errors.
2. Inspect full APNIC range coverage, registration identity and applicable ancestor/child references. Missing or contradictory identity is inconclusive. Do not infer ownership from BGP origin or a maintainer name alone.
3. Inspect the selected publication outcome. An overridden parent must not substitute for a failed child feed. Report absent, unsafe, conflicting or unavailable references without bypassing them.
4. For third-party data, inspect the supporting authorised routing block and containment. A ROA length restriction on a hypothetical geographic more-specific is not itself a failed real route.
5. Inspect RIPEstat response shape, timestamps, origin filtering and actual route RPKI states. Do not change ROAs or routing to make this repository's checks pass.
6. For publication mismatch, confirm the target revision has not been superseded, inspect cache evidence and respect the convergence deadline. Do not rewrite URLs, auto-publish a candidate or roll back.
7. Inspect the safe report and tracking issue. Never copy raw contact records, credentials, private addresses or unchecked remote text into public diagnostics.

Report the failing stage, safe evidence, checks not reached and next action in PLANS.md. Do not weaken security limits, enable ambient credentials/proxies, bypass protections or reinterpret an unavailable lookup as NotFound.

## External Actions

Implementation permission does not automatically authorise committing, pushing, changing repository protections, creating issues, activating workflows or modifying network/RIR/RPKI state. Confirm the approved scope before those actions.

PR jobs remain unprivileged. Only trusted main/scheduled/manual reporting may receive issue-write permission. Test issue lifecycle and publication retries with fake transports/clocks; never use internal services as security test targets.

## Validation Entry Points

Use the dependency/setup instructions in [README.md](README.md). Keep these entry points compatible:

```bash
python3 scripts/validate_geofeed.py geofeed.csv
python3 scripts/check_authority.py --geofeed geofeed.csv --asn 149794
```

The first command is local; the second queries external services. See PLANS.md for current validation results and any unverified activation steps.

`check_authority.py` defaults to `--mode audit`. `--json-report PATH` writes the same structured result printed to stdout. Publication mode additionally requires `--repository OWNER/REPO --revision FULL_SHA`; the local CSV must equal that commit's blob. Do not use it to claim an uncommitted candidate is published. Exit codes are 0 for pass/warning, 1 for failure, 2 for incomplete and 3 for superseded; inspect stages and findings as well as the exit code.

For a local change review, `validate_geofeed.py --base PATH geofeed.csv` reports added, removed and changed prefix locations without rewriting either file. Run offline tests with `python3 -m unittest discover -s tests`.
