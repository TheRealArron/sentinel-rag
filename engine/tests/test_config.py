"""Settings resolution.

Configuration bugs in this project are quiet by nature: nothing raises, the
engine simply reads or writes somewhere other than where the operator believes
it does. These tests pin the two properties that make a path knob trustworthy —
that it moves what it claims to move, and that naming a path still wins.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _clean_path_env(monkeypatch):
    for name in (
        "SENTINEL_DATA_DIR", "SENTINEL_EVENTS_PATH", "SENTINEL_ADVISORY_DIR",
        "SENTINEL_CHROMA_DIR", "SENTINEL_INDEX_DIR", "SENTINEL_AUDIT_LOG",
    ):
        monkeypatch.delenv(name, raising=False)


class TestDataDirectory:
    def test_one_variable_relocates_the_whole_working_set(self, monkeypatch, tmp_path):
        """SENTINEL_DATA_DIR used to move almost nothing.

        Each path defaulted to ``<repo>/data/...`` independently, so pointing this
        at a mounted disk relocated the directory created on startup while events,
        the index, the vector store and the audit log stayed on the system disk.
        Nothing failed — which is the whole problem with a path bug.
        """
        monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "elsewhere"))
        settings = Settings()

        root = tmp_path / "elsewhere"
        assert settings.data_dir == root
        assert settings.events_path == root / "events.jsonl"
        assert settings.advisory_dir == root / "advisories"
        assert settings.chroma_dir == root / "chroma"
        assert settings.index_dir == root / "index"
        assert settings.audit_log == root / "audit.log"

    def test_the_default_layout_is_unchanged(self):
        settings = Settings()
        assert settings.events_path == settings.data_dir / "events.jsonl"
        assert settings.index_dir == settings.data_dir / "index"
        assert settings.data_dir.name == "data"

    def test_naming_a_path_explicitly_still_wins(self, monkeypatch, tmp_path):
        # The compose file and the test fixtures set every variable; a derived
        # default must never override one that was asked for.
        monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
        monkeypatch.setenv("SENTINEL_EVENTS_PATH", str(tmp_path / "custom" / "events.jsonl"))
        monkeypatch.setenv("SENTINEL_AUDIT_LOG", "/var/log/sentinel-audit.log")
        settings = Settings()

        assert settings.events_path == tmp_path / "custom" / "events.jsonl"
        assert settings.audit_log == Path("/var/log/sentinel-audit.log")
        # The ones that were not named still follow data_dir.
        assert settings.index_dir == tmp_path / "data" / "index"

    def test_replace_keeps_the_path_it_is_handed(self, monkeypatch, tmp_path):
        """dataclasses.replace must not have the derivation undo its argument.

        cli.cmd_hub and several tests build a variant with replace(). If the
        derivation keyed on "is this environment variable set?" instead of on an
        unresolved marker, replacing a path while its variable happened to be
        unset would silently put the default back — a caller's explicit argument
        ignored depending on the environment.
        """
        from dataclasses import replace

        monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
        variant = replace(Settings(), events_path=tmp_path / "somewhere" / "events.jsonl")
        assert variant.events_path == tmp_path / "somewhere" / "events.jsonl"
        assert variant.index_dir == tmp_path / "data" / "index"

    def test_a_constructor_argument_is_honoured(self, tmp_path):
        assert Settings(index_dir=tmp_path / "given").index_dir == tmp_path / "given"

    def test_no_resolved_path_is_the_internal_marker(self):
        # If the marker ever survived resolution it would be used as a real path.
        settings = Settings()
        for name in ("data_dir", "events_path", "advisory_dir", "chroma_dir", "index_dir", "audit_log"):
            assert "\0" not in str(getattr(settings, name))

    def test_ensure_dirs_creates_what_it_relocated(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "fresh"))
        settings = Settings()
        settings.ensure_dirs()
        assert (tmp_path / "fresh" / "index").is_dir()
        assert (tmp_path / "fresh" / "chroma").is_dir()


class TestRedaction:
    def test_secrets_are_masked_and_paths_are_strings(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "abcdef123456")
        monkeypatch.setenv("SENTINEL_API_TOKEN", "topsecret")
        redacted = Settings().redacted()

        assert redacted["gemini_api_key"] == "set (12 chars)"
        assert redacted["api_token"] == "set (9 chars)"
        assert redacted["openai_api_key"] == "unset"
        assert isinstance(redacted["data_dir"], str)
        # Nothing in the payload may be the secret itself.
        assert "topsecret" not in str(redacted)
        assert "abcdef123456" not in str(redacted)


class TestCaching:
    def test_refresh_rereads_the_environment(self, monkeypatch):
        first = get_settings(refresh=True)
        try:
            monkeypatch.setenv("SENTINEL_TOP_K", str(first.top_k + 3))
            assert get_settings().top_k == first.top_k, "cached settings should not change"
            assert get_settings(refresh=True).top_k == first.top_k + 3
        finally:
            # The cache is process-wide, so a test that refreshes it has to put it
            # back before the environment it was built from disappears.
            monkeypatch.delenv("SENTINEL_TOP_K", raising=False)
            get_settings(refresh=True)
