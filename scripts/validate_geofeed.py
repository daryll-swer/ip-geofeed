#!/usr/bin/env python3
"""Validate candidate CSV and policy without external dependencies at runtime."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from feed import POLICY_PATH, InputError, load_policy, net_key, parse_feed, read_bounded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("geofeed", type=Path, nargs="?", default=Path("geofeed.csv"))
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--base", type=Path, help="Previous feed for a location-change review")
    args = parser.parse_args()
    try:
        load_policy(args.policy)
        feed = parse_feed(read_bounded(args.geofeed), own=True)
        if args.base:
            raw = read_bounded(args.base)
            old = parse_feed(raw, own=False).rows if raw else {}
            for prefix in sorted(old.keys() | feed.rows.keys(), key=net_key):
                before, after = old.get(prefix), feed.rows.get(prefix)
                if before != after:
                    print(json.dumps({"prefix": str(prefix), "before": before, "after": after},
                                     ensure_ascii=True))
    except (OSError, InputError) as exc:
        print(f"ERROR: {exc if isinstance(exc, InputError) else 'local-file-unavailable'}",
              file=sys.stderr)
        return 1
    for code, line in feed.warnings:
        print(f"WARNING: {code} (line {line})")
    print(f"OK: validated {len(feed.rows)} geofeed prefixes and policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
