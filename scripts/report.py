"""Stable, public-safe findings shared by audit, publication and issue rendering."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from feed import Network
from transport import public_ip

STAGES = {
    "audit": ("input", "bgp", "rpki", "authority", "feeds"),
    "publication": ("input", "currency", "authority", "publication"),
}
SEVERITY = {"unevaluated": -1, "info": 0, "pass": 0, "warning": 1, "failure": 2,
            "incomplete": 3, "superseded": 4}
MAX_FINDINGS = 100
CODE = re.compile(r"[a-z][a-z0-9-]{0,62}")
SHA = re.compile(r"[0-9a-f]{40}")


@dataclass
class Report:
    mode: str
    revision: str | None = None
    stages: dict[str, str] = field(init=False)
    findings: list[dict[str, str]] = field(default_factory=list)
    observations: dict[str, int | str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.stages = dict.fromkeys(STAGES[self.mode], "unevaluated")

    def done(self, stage: str) -> None:
        if self.stages[stage] == "unevaluated":
            self.stages[stage] = "pass"

    def add(self, stage: str, severity: str, code: str, prefix: Network | None = None) -> None:
        if not CODE.fullmatch(code):
            raise ValueError("invalid diagnostic code")
        if severity != "info" and SEVERITY[severity] > SEVERITY[self.stages[stage]]:
            self.stages[stage] = severity
        finding = {"stage": stage, "severity": severity, "code": code}
        if (prefix is not None and public_ip(str(prefix.network_address))
                and public_ip(str(prefix.broadcast_address))):
            finding["prefix"] = str(prefix)
        if finding in self.findings:
            return
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(finding)
        elif severity != "info":
            self.stages[stage] = max(("incomplete", self.stages[stage]), key=SEVERITY.__getitem__)
            marker = {"stage": stage, "severity": "incomplete", "code": "finding-limit"}
            if marker not in self.findings:
                self.findings[MAX_FINDINGS - 1] = marker

    @property
    def outcome(self) -> str:
        maximum = max(self.stages.values(), key=SEVERITY.__getitem__)
        if SEVERITY[maximum] > 0:
            return maximum
        return "incomplete" if "unevaluated" in self.stages.values() else "pass"

    def document(self) -> dict:
        return {"version": 1, "mode": self.mode, "revision": self.revision,
                "outcome": self.outcome, "stages": self.stages, "findings": self.findings,
                "observations": self.observations}
