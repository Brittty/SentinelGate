"""IDPS signature engine for SentinelGate.

Loads rules from idps/rules.yaml, pre-compiles regexes, and inspects request
components for signature matches. Input is normalized (URL-decoded up to 2
passes, lowercased, null bytes stripped) before matching. The engine never
raises and enforces a per-request time budget.
"""

from __future__ import annotations

import re
import time
from urllib.parse import unquote

import yaml

RULES_PATH = "idps/rules.yaml"
TIME_BUDGET_SECONDS = 0.005  # 5 ms per request


def _normalize(value: str) -> str:
    """URL-decode up to 2 passes, lowercase, strip null bytes."""
    if not value:
        return value
    decoded = value
    for _ in range(2):
        try:
            decoded = unquote(decoded)
        except Exception:
            break
    decoded = decoded.lower()
    decoded = decoded.replace("\x00", " ")
    return decoded


class Engine:
    """Signature matching engine.

    Rules are loaded once and compiled. ``inspect()`` returns a list of hits;
    it never raises and respects a per-request time budget.
    """

    def __init__(self, rules_path: str = RULES_PATH):
        self.rules_path = rules_path
        self.compiled: list[dict] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Load and pre-compile rules from YAML."""
        self.compiled = []
        try:
            with open(self.rules_path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            return
        for rule in data.get("rules", []):
            try:
                self.compiled.append(
                    {
                        "id": rule.get("id", ""),
                        "name": rule.get("name", ""),
                        "attack_type": rule.get("attack_type", ""),
                        "severity": rule.get("severity", "low"),
                        "mitre_id": rule.get("mitre_id", ""),
                        "targets": rule.get("targets", []),
                        "regex": re.compile(rule.get("pattern", "")),
                    }
                )
            except re.error:
                continue

    def inspect(
        self,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: str,
    ) -> list[dict]:
        """Inspect request components for rule hits.

        Returns a list of hit dicts (id, name, attack_type, severity, mitre_id,
        target). Never raises; returns [] on any error.
        """
        hits: list[dict] = []
        start = time.perf_counter()
        fields = {
            "path": path or "",
            "query": query or "",
            "body": body or "",
            "headers": " ".join(f"{k}:{v}" for k, v in (headers or {}).items()),
            "user_agent": (headers or {}).get("user-agent", ""),
        }
        normalized = {k: _normalize(v) for k, v in fields.items()}
        try:
            for rule in self.compiled:
                if time.perf_counter() - start > TIME_BUDGET_SECONDS:
                    break
                for target in rule["targets"]:
                    value = normalized.get(target, "")
                    if rule["regex"].search(value):
                        hits.append(
                            {
                                "id": rule["id"],
                                "name": rule["name"],
                                "attack_type": rule["attack_type"],
                                "severity": rule["severity"],
                                "mitre_id": rule["mitre_id"],
                                "target": target,
                            }
                        )
                        break  # one hit per rule per request
        except Exception:
            return hits
            pass
        return hits