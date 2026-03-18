"""Tests for alerter.py — alert filtering and message building."""

from __future__ import annotations

import os
import sys

import pytest

from fim.alerter import should_alert, _build_email_body, _build_webhook_payload


class TestShouldAlert:
    """Unit tests for the ``should_alert()`` filter function."""

    def test_critical_severity_triggers(self):
        doc = {"severity": "CRITICAL", "event.type": "MODIFIED"}
        assert should_alert(doc) is True

    def test_ransomware_event_triggers(self):
        doc = {"severity": "HIGH", "event.type": "RANSOMWARE_PATTERN"}
        assert should_alert(doc) is True

    def test_high_severity_no_trigger(self):
        doc = {"severity": "HIGH", "event.type": "MODIFIED"}
        assert should_alert(doc) is False

    def test_medium_severity_no_trigger(self):
        doc = {"severity": "MEDIUM", "event.type": "CREATED"}
        assert should_alert(doc) is False

    def test_low_severity_no_trigger(self):
        doc = {"severity": "LOW", "event.type": "CREATED"}
        assert should_alert(doc) is False

    def test_empty_doc_no_trigger(self):
        assert should_alert({}) is False


class TestEmailBody:
    """Unit tests for the email body builder."""

    def test_contains_event_type(self):
        doc = {
            "event.type": "MODIFIED",
            "severity": "CRITICAL",
            "file.path": "/etc/passwd",
            "@timestamp": "2026-01-01T00:00:00Z",
            "host.name": "server01",
            "host.ip": "10.0.0.1",
            "hash.old": "abc",
            "hash.new": "def",
        }
        body = _build_email_body(doc)
        assert "MODIFIED" in body
        assert "CRITICAL" in body
        assert "/etc/passwd" in body
        assert "server01" in body

    def test_missing_fields_show_na(self):
        body = _build_email_body({})
        assert "UNKNOWN" in body or "N/A" in body


class TestWebhookPayload:
    """Unit tests for the webhook payload builder."""

    def test_has_text_field(self):
        doc = {
            "severity": "CRITICAL",
            "event.type": "MODIFIED",
            "file.path": "/etc/shadow",
            "host.name": "server01",
            "@timestamp": "2026-01-01T00:00:00Z",
        }
        payload = _build_webhook_payload(doc)
        assert "text" in payload
        assert "CRITICAL" in payload["text"]
        assert "/etc/shadow" in payload["text"]
