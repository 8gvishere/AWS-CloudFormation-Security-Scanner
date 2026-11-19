"""Minimal integration tests: parser -> rules -> CLI result."""

import json
from pathlib import Path

from scanner.__main__ import main

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_cli_insecure_returns_nonzero(capsys):
    code = main([str(SAMPLES / "02_insecure_ssh.yaml")])
    out = capsys.readouterr().out
    assert code == 1
    assert "[FAIL]" in out


def test_cli_secure_returns_zero(capsys):
    code = main([str(SAMPLES / "03_secure_ssh.yaml")])
    assert code == 0
    assert "[PASS]" in capsys.readouterr().out


def test_cli_json_is_machine_readable(capsys):
    code = main([str(SAMPLES / "04_dynamic_source.yaml"), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["results"][0]["status"] == "REVIEW"


def test_cli_bad_file_returns_two(capsys):
    code = main([str(SAMPLES / "nothing.yaml")])
    assert code == 2
    assert "Template error:" in capsys.readouterr().err
