"""Tests for gateway.logger."""

from __future__ import annotations

import json
import os
import shutil
import tempfile

from gateway.logger import MAX_FIELD, log_event


def test_log_event_writes_json_line():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        log_event(
            path,
            {
                "timestamp": "2024-01-01T12:00:00Z",
                "source_ip": "127.0.0.1",
                "method": "GET",
                "path": "/search",
                "query": "q=hello",
                "status": 200,
                "user_agent": "Mozilla/5.0",
                "latency_ms": 12.5,
                "action": "allow",
                "source": "gateway",
            },
        )
        with open(path, encoding="utf-8") as fh:
            line = fh.readline().strip()
        data = json.loads(line)
        assert data["source_ip"] == "127.0.0.1"
        assert data["method"] == "GET"
        assert data["action"] == "allow"
    finally:
        os.unlink(path)


def test_log_event_sanitizes_newlines():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        log_event(
            path,
            {
                "timestamp": "2024-01-01T12:00:00Z",
                "source_ip": "127.0.0.1",
                "method": "GET",
                "path": "/search",
                "user_agent": "bad\r\nua",
                "status": 200,
                "action": "allow",
                "source": "gateway",
            },
        )
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.readline())
        assert "\n" not in data["user_agent"]
        assert "\r" not in data["user_agent"]
    finally:
        os.unlink(path)


def test_log_event_caps_field_length():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        long_value = "x" * 5000
        log_event(
            path,
            {
                "timestamp": "2024-01-01T12:00:00Z",
                "source_ip": "127.0.0.1",
                "method": "GET",
                "path": "/search",
                "user_agent": long_value,
                "status": 200,
                "action": "allow",
                "source": "gateway",
            },
        )
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.readline())
        assert len(data["user_agent"]) <= MAX_FIELD  # noqa: PLR2004
    finally:
        os.unlink(path)


def test_log_event_creates_directory():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    os.unlink(path)
    dir_path = os.path.dirname(path)
    nested = os.path.join(dir_path, "sub", "events.jsonl")
    try:
        log_event(
            nested,
            {
                "timestamp": "2024-01-01T12:00:00Z",
                "source_ip": "127.0.0.1",
                "method": "GET",
                "path": "/",
                "status": 200,
                "action": "allow",
                "source": "gateway",
            },
        )
        assert os.path.isfile(nested)
    finally:
        shutil.rmtree(os.path.join(dir_path, "sub"), ignore_errors=True)