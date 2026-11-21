"""Main-revision and workflow-run currency, without access to discovered feeds."""

from __future__ import annotations

import re
from urllib.parse import urlencode

from evidence import timestamp
from report import SHA
from transport import GITHUB, Deadline, FetchError, Transport, decode_json

TRUSTED_EVENTS = {"push", "schedule", "workflow_dispatch"}
WORKFLOW = "live-audit.yml"
REPO = re.compile(r"[A-Za-z0-9_-]{1,100}/[A-Za-z0-9_.-]{1,100}")


def repository_name(value: str) -> str:
    if not REPO.fullmatch(value) or value.split("/")[1] in (".", ".."):
        raise ValueError("invalid repository")
    return value


def current_main(transport: Transport, repository: str, revision: str, deadline: Deadline) -> bool:
    name = repository_name(repository)
    result = decode_json(transport.get(f"{GITHUB}/repos/{name}/git/ref/heads/main",
                                       deadline.child(45), fixed=True, fresh=True, limit=65536))
    try:
        sha = result["object"]["sha"]
        if (result["ref"] != "refs/heads/main" or result["object"]["type"] != "commit"
                or not SHA.fullmatch(sha)):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise FetchError("malformed-main-reference") from None
    return sha == revision


def current_run(transport: Transport, repository: str, revision: str, run_id: int, attempt: int,
                token: str, deadline: Deadline) -> bool:
    root = f"/repos/{repository_name(repository)}/actions"

    def get(path: str) -> dict:
        return decode_json(transport.github_write_api(root + path, deadline, token))

    def trusted(run: dict) -> bool:
        return (run["event"] in TRUSTED_EVENTS and run["head_branch"] == "main"
                and run["head_sha"] == revision
                and run["head_repository"]["full_name"].lower() == repository.lower())

    def order(run: dict) -> tuple[int, int, int]:
        keys = (run["run_number"], run["run_attempt"], run["id"])
        if any(type(v) is not int or v < 1 for v in keys):
            raise ValueError
        return keys

    try:
        origin = get(f"/runs/{run_id}")
        if not trusted(origin) or order(origin)[1:] != (attempt, run_id):
            return False
        current = order(origin)
        created = timestamp(origin["created_at"]).isoformat(timespec="seconds")
        # Exclude historical runs on an unchanged SHA. Never assume list ordering.
        found = False
        for page in range(1, 11):
            query = urlencode({"branch": "main", "head_sha": revision, "created": ">=" + created,
                               "per_page": 50, "page": page})
            result = get(f"/workflows/{WORKFLOW}/runs?{query}")
            runs, count = result["workflow_runs"], result["total_count"]
            if not isinstance(runs, list) or len(runs) > 50 or type(count) is not int or count < len(runs):
                raise ValueError
            for run in runs:
                if trusted(run):
                    candidate = order(run)
                    if candidate > current:
                        return False
                    found |= candidate == current
            if page * 50 >= count:
                if not found:
                    raise ValueError
                return True
            if len(runs) != 50:
                raise ValueError
        raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise FetchError("workflow-currency-unavailable") from None
