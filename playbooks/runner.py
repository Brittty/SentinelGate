"""Playbook runner for SentinelGate automated response.

Loads playbooks from YAML and executes steps with approval gates.
"""

from __future__ import annotations

import os
from typing import Any

import yaml

PLAYBOOKS_DIR = "playbooks"


def _load_playbook(name: str) -> dict[str, Any] | None:
    """Load a playbook by name from playbooks/*.yaml."""
    path = os.path.join(PLAYBOOKS_DIR, f"{name}.yaml")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None


def list_playbooks() -> list[str]:
    """List available playbook names."""
    if not os.path.isdir(PLAYBOOKS_DIR):
        return []
    return [
        f[:-5]
        for f in os.listdir(PLAYBOOKS_DIR)
        if f.endswith(".yaml") and os.path.isfile(os.path.join(PLAYBOOKS_DIR, f))
    ]


def run_playbook(
    name: str,
    context: dict[str, Any],
    audit_chain: Any,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run a playbook with the given context.

    Args:
        name: Playbook name (e.g., "brute_force")
        context: Dict with ip, alert_id, attack_type, etc.
        audit_chain: HashChain instance for logging
        dry_run: If True, simulate without executing actions

    Returns:
        Dict with executed_steps, skipped_steps, errors
    """
    playbook = _load_playbook(name)
    if not playbook:
        return {"error": f"Playbook '{name}' not found", "executed_steps": []}

    steps = playbook.get("steps", [])
    executed = []
    skipped = []
    errors = []

    for step in steps:
        step_name = step.get("name", "unnamed")
        action = step.get("action", "")
        params = step.get("params", {})
        approve = step.get("approve", False)

        # Log step to audit chain
        audit_chain.append(
            {
                "type": "playbook_step",
                "playbook": name,
                "step": step_name,
                "action": action,
                "context": context,
                "dry_run": dry_run,
            }
        )

        if dry_run:
            executed.append({"step": step_name, "action": action, "status": "simulated"})
            continue

        # In a real implementation, this would dispatch to actual action handlers
        # For now, we just log what would be executed
        if approve:
            # Steps requiring approval would prompt or check permissions here
            executed.append({"step": step_name, "action": action, "status": "requires_approval"})
        else:
            executed.append({"step": step_name, "action": action, "status": "executed"})

    return {
        "playbook": name,
        "executed_steps": executed,
        "skipped_steps": skipped,
        "errors": errors,
    }


def get_playbook_for_alert(alert_rule: str, severity: str) -> str | None:
    """Find a playbook that matches the alert criteria.

    Returns playbook name or None if no match.
    """
    for pb_name in list_playbooks():
        pb = _load_playbook(pb_name)
        if not pb:
            continue
        trigger = pb.get("trigger", {})
        if trigger.get("alert_rule") == alert_rule:
            return pb_name
    return None
