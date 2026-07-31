"""Argument parsing.

These exist because CI caught what local testing did not: ``--json`` was only
accepted *before* the subcommand, so the natural ``sentinel stats --json``
failed with "unrecognized arguments". Argument order is exactly the kind of thing
that works in every invocation you happen to try by hand and breaks in the first
script somebody writes.
"""

from __future__ import annotations

import argparse

import pytest

from sentinel.cli import build_parser

SUBCOMMANDS = ["index", "analyze", "serve", "stats", "warm", "demo"]


class TestGlobalFlagPositions:
    @pytest.mark.parametrize("command", SUBCOMMANDS)
    def test_json_after_the_subcommand(self, command):
        args = build_parser().parse_args([command, "--json"])
        assert args.json is True

    @pytest.mark.parametrize("command", SUBCOMMANDS)
    def test_json_before_the_subcommand(self, command):
        args = build_parser().parse_args(["--json", command])
        assert args.json is True

    @pytest.mark.parametrize("command", SUBCOMMANDS)
    def test_json_defaults_to_false(self, command):
        assert build_parser().parse_args([command]).json is False

    def test_json_before_the_subcommand_is_not_clobbered(self):
        # The regression the SUPPRESS defaults exist to prevent: an ordinary
        # store_true on the subparser writes False over the earlier --json.
        assert build_parser().parse_args(["--json", "stats"]).json is True

    def test_json_works_on_subcommands_with_positionals(self):
        args = build_parser().parse_args(["search", "brute force", "--json"])
        assert args.json is True
        assert args.query == "brute force"

    def test_json_works_on_subcommands_with_required_flags(self):
        args = build_parser().parse_args(["block", "203.0.113.45", "--score", "97", "--json"])
        assert args.json is True
        assert args.ip == "203.0.113.45"
        assert args.score == 97


class TestLangFlag:
    def test_defaults_to_both(self):
        assert build_parser().parse_args(["analyze"]).lang == "both"

    @pytest.mark.parametrize("position", ["before", "after"])
    def test_accepted_in_either_position(self, position):
        argv = ["--lang", "ja", "analyze"] if position == "before" else ["analyze", "--lang", "ja"]
        assert build_parser().parse_args(argv).lang == "ja"

    def test_rejects_an_unknown_value(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["analyze", "--lang", "fr"])

    def test_search_uses_languages_not_lang_for_its_corpus_filter(self):
        # --lang means "output language" everywhere; the corpus filter is
        # --languages. Having one name mean two things is a trap.
        args = build_parser().parse_args(["search", "q", "--languages", "en,ja", "--lang", "ja"])
        assert args.languages == "en,ja"
        assert args.lang == "ja"


class TestSubcommandArguments:
    def test_a_subcommand_is_required(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_unknown_subcommand_exits(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["nope"])

    def test_block_requires_a_score(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["block", "203.0.113.45"])

    def test_every_subcommand_binds_a_handler(self):
        parser = build_parser()
        for command in [*SUBCOMMANDS, "search", "block", "unblock"]:
            argv = {
                "search": ["search", "q"],
                "block": ["block", "203.0.113.45", "--score", "99"],
                "unblock": ["unblock", "203.0.113.45"],
            }.get(command, [command])
            args = parser.parse_args(argv)
            assert callable(args.func), f"{command} has no handler"

    def test_index_flags(self):
        args = build_parser().parse_args(["index", "--rebuild", "--advisories-only"])
        assert args.rebuild is True
        assert args.advisories_only is True

    def test_analyze_flags(self):
        args = build_parser().parse_args(["analyze", "--min-score", "80", "--limit", "5"])
        assert args.min_score == 80
        assert args.limit == 5

    def test_serve_flags(self):
        args = build_parser().parse_args(["serve", "--stdlib", "--port", "9000"])
        assert args.stdlib is True
        assert args.port == 9000


class TestHelpIsWellFormed:
    def test_top_level_help_exits_cleanly(self, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--help"])
        assert exc.value.code == 0
        assert "Sentinel RAG" in capsys.readouterr().out

    @pytest.mark.parametrize("command", [*SUBCOMMANDS, "search", "block", "unblock"])
    def test_subcommand_help_exits_cleanly(self, command, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args([command, "--help"])
        assert exc.value.code == 0
        assert "--json" in capsys.readouterr().out

    def test_suppressed_defaults_do_not_leak_into_the_namespace(self):
        # argparse.SUPPRESS must not appear as a value anywhere.
        args = build_parser().parse_args(["stats"])
        for name, value in vars(args).items():
            assert value != argparse.SUPPRESS, f"{name} leaked SUPPRESS"
