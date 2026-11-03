"""Tests for SOC features: cases, MITRE mapping, intel enrichment, playbooks."""

from __future__ import annotations

import sqlite3

import pytest

from cases.manager import CaseManager
from mitre.mapper import get_mitre_info, tag_rule


@pytest.fixture
def case_manager() -> CaseManager:
    conn = sqlite3.connect(":memory:")
    return CaseManager(conn)


def test_create_case(case_manager: CaseManager):
    case_id = case_manager.create_case(
        title="Test incident",
        severity="high",
        assignee="analyst1",
    )
    assert case_id.startswith("CASE-")

    case = case_manager.get_case(case_id)
    assert case is not None
    assert case["title"] == "Test incident"
    assert case["severity"] == "high"
    assert case["status"] == "open"
    assert case["assignee"] == "analyst1"


def test_update_case(case_manager: CaseManager):
    case_id = case_manager.create_case("Test", "medium")

    result = case_manager.update_case(
        case_id,
        status="investigating",
        assignee="analyst2",
        actor="admin",
    )
    assert result is True

    case = case_manager.get_case(case_id)
    assert case["status"] == "investigating"
    assert case["assignee"] == "analyst2"


def test_case_timeline(case_manager: CaseManager):
    case_id = case_manager.create_case("Test", "low")

    case_manager.add_timeline_entry(case_id, "Evidence collected", "analyst1")
    case_manager.update_case(case_id, status="contained", actor="analyst1")

    timeline = case_manager.get_timeline(case_id)
    assert len(timeline) >= 3  # create + manual + update
    assert any("Evidence collected" in e["entry"] for e in timeline)
    assert any("contained" in e["entry"] for e in timeline)


def test_list_cases(case_manager: CaseManager):
    case_manager.create_case("Case 1", "high")
    case_manager.create_case("Case 2", "medium")

    cases = case_manager.list_cases()
    assert len(cases) == 2

    open_cases = case_manager.list_cases(status="open")
    assert len(open_cases) == 2


def test_mitre_mapping():
    info = get_mitre_info("T1110")
    assert info["name"] == "Brute Force"
    assert info["tactic"] == "Credential Access"
    assert "brute_force" in info["detection_rules"]


def test_mitre_tag_rule():
    technique_id = tag_rule("brute_force")
    assert technique_id == "T1110"

    technique_id = tag_rule("sqli")
    assert technique_id == "T1190"

    technique_id = tag_rule("nonexistent")
    assert technique_id == ""


def test_reputation_unconfigured():
    from intel.enrich import ReputationClient

    conn = sqlite3.connect(":memory:")
    client = ReputationClient(conn, api_key="")

    # Without API key, should return 0.0
    reputation = client.lookup("192.0.2.1")
    assert reputation == 0.0


def test_playbook_list():
    from playbooks.runner import list_playbooks

    playbooks = list_playbooks()
    assert "brute_force" in playbooks
    assert "sqli" in playbooks
    assert "scan" in playbooks


def test_playbook_run_dry():
    from audit.hashchain import HashChain
    from playbooks.runner import run_playbook

    conn = sqlite3.connect(":memory:")
    chain = HashChain(conn)

    context = {"ip": "192.0.2.1", "alert_id": "test-123"}
    result = run_playbook("brute_force", context, chain, dry_run=True)

    assert "executed_steps" in result
    assert len(result["executed_steps"]) > 0
    assert all(s["status"] == "simulated" for s in result["executed_steps"])
