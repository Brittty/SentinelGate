"""Shared event schema for SentinelGate.

Defines the canonical :class:`Event` Pydantic v2 model used across the
gateway, collectors, correlation engines, ML detector, and dashboard.
All string fields are sanitized (control characters and newlines removed,
length capped) on input to prevent log/header injection.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ACTION = Literal["allow", "throttle", "block"]
_SOURCE = Literal["gateway", "suricata", "wazuh"]

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NEWLINE_RE = re.compile(r"[\r\n]+")


def _sanitize(value: str, max_len: int = 2048) -> str:
    """Remove control characters/newlines and cap length."""
    value = _NEWLINE_RE.sub(" ", value)
    value = _CONTROL_CHARS_RE.sub("", value)
    return value[:max_len]


class Event(BaseModel):
    """Canonical security event shared by all SentinelGate components."""

    model_config = ConfigDict(str_strip_whitespace=True)

    timestamp: datetime
    source_ip: str = Field(max_length=64)
    method: str = Field(max_length=16)
    path: str = Field(max_length=2048)
    query: str = Field(default="", max_length=4096)
    status: int = Field(default=200, ge=100, le=599)
    user_agent: str = Field(default="", max_length=1024)
    latency_ms: float = Field(default=0.0, ge=0.0)
    rule_hit: str = Field(default="", max_length=256)
    attack_type: str = Field(default="", max_length=128)
    ml_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    action: _ACTION = "allow"
    source: _SOURCE = "gateway"

    @field_validator("*", mode="before")
    @classmethod
    def _sanitize_fields(cls, value: object) -> object:
        if isinstance(value, str):
            return _sanitize(value)
        return value