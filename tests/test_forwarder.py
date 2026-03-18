"""Tests for forwarder.py — severity classification and ECS document builder."""

from __future__ import annotations

import os
import sys

import pytest

from fim.forwarder import severity, build_doc


class TestSeverity:
    """Unit tests for the ``severity()`` classification function."""

    def test_etc_passwd_is_critical(self):
        assert severity("/etc/passwd", "MODIFIED") == "CRITICAL"

    def test_etc_shadow_is_critical(self):
        assert severity("/etc/shadow", "MODIFIED") == "CRITICAL"

    def test_ssh_authorized_keys_is_critical(self):
        assert severity("/home/user/.ssh/authorized_keys", "CREATED") == "CRITICAL"

    def test_sudoers_is_critical(self):
        assert severity("/etc/sudoers", "MODIFIED") == "CRITICAL"

    def test_crontab_is_critical(self):
        assert severity("/etc/crontab", "MODIFIED") == "CRITICAL"

    def test_ssh_dir_is_high(self):
        assert severity("/home/user/.ssh/known_hosts", "CREATED") == "HIGH"

    def test_cron_dir_is_high(self):
        assert severity("/etc/cron.d/malicious", "CREATED") == "HIGH"

    def test_root_home_is_high(self):
        assert severity("/root/.bashrc_new", "CREATED") == "HIGH"

    def test_bashrc_is_high(self):
        assert severity("/home/user/.bashrc", "MODIFIED") == "HIGH"

    def test_deletion_is_high(self):
        """Any deletion should be classified as HIGH severity."""
        assert severity("/tmp/random_file.txt", "DELETED") == "HIGH"

    def test_etc_config_is_medium(self):
        assert severity("/etc/nginx/sites-enabled/default", "MODIFIED") == "MEDIUM"

    def test_var_log_is_medium(self):
        assert severity("/var/log/auth.log", "MODIFIED") == "MEDIUM"

    def test_cert_file_is_medium(self):
        assert severity("/etc/ssl/server.pem", "CREATED") == "MEDIUM"

    def test_var_www_is_medium(self):
        assert severity("/var/www/html/index.html", "MODIFIED") == "MEDIUM"

    def test_normal_file_is_low(self):
        assert severity("/home/user/documents/report.pdf", "CREATED") == "LOW"

    def test_tmp_file_is_low(self):
        assert severity("/tmp/build_output.o", "MODIFIED") == "LOW"


class TestBuildDoc:
    """Unit tests for the ``build_doc()`` ECS document builder."""

    def test_contains_required_fields(self):
        """ECS document must contain all required fields."""
        doc = build_doc("CREATED", "/etc/test.conf", new_hash="abc123")
        required_keys = [
            "@timestamp", "event.type", "file.path", "severity",
            "host.name", "host.ip", "tags",
        ]
        for key in required_keys:
            assert key in doc, f"Missing ECS field: {key}"

    def test_event_type_set_correctly(self):
        doc = build_doc("MODIFIED", "/etc/test.conf")
        assert doc["event.type"] == "MODIFIED"

    def test_file_path_set_correctly(self):
        doc = build_doc("CREATED", "/home/user/file.txt")
        assert doc["file.path"] == "/home/user/file.txt"

    def test_hashes_stored(self):
        doc = build_doc("MODIFIED", "/f", old_hash="old123", new_hash="new456")
        assert doc["hash.old"] == "old123"
        assert doc["hash.new"] == "new456"
        assert doc["hash.changed"] is True

    def test_hash_unchanged(self):
        doc = build_doc("MODIFIED", "/f", old_hash="same", new_hash="same")
        assert doc["hash.changed"] is False

    def test_tags_include_fim(self):
        doc = build_doc("CREATED", "/f")
        assert "fim" in doc["tags"]
        assert "integrity" in doc["tags"]

    def test_timestamp_is_iso_format(self):
        doc = build_doc("CREATED", "/f")
        ts = doc["@timestamp"]
        # ISO-8601 timestamps contain 'T' and '+' or 'Z'
        assert "T" in ts
