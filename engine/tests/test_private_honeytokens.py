"""scripts/check-private-honeytokens.py: a deployment must not run the public canaries.

config/honeytokens.json is committed to a public repository, so its values are
known. The check exists so a real host cannot quietly arm them, and each case
below pins one way it could otherwise be fooled.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "check-private-honeytokens.py"
PUBLIC = REPO_ROOT / "config" / "honeytokens.json"


def run(local: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), str(local), str(PUBLIC)],
        capture_output=True,
        text=True,
        check=False,
    )


def write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_private_values_pass(tmp_path: Path) -> None:
    local = write(
        tmp_path / "local.json",
        {"users": ["svc-db-07", {"value": "ops_archive", "note": "x"}], "paths": ["/srv/.dbpass"]},
    )
    result = run(local)
    assert result.returncode == 0, result.stderr
    assert "3 canary value(s)" in result.stdout


def test_missing_file_fails(tmp_path: Path) -> None:
    result = run(tmp_path / "absent.json")
    assert result.returncode == 1
    assert "does not exist" in result.stderr


def test_verbatim_copy_of_public_set_fails(tmp_path: Path) -> None:
    # The likeliest mistake: `cp honeytokens.json honeytokens.local.json` and
    # never editing it.
    local = tmp_path / "local.json"
    local.write_text(PUBLIC.read_text(encoding="utf-8"), encoding="utf-8")
    result = run(local)
    assert result.returncode == 1
    assert "admin_backup" in result.stderr


def test_single_reused_value_fails_case_insensitively(tmp_path: Path) -> None:
    # The ingestor folds case, so ADMIN_BACKUP is the same canary as admin_backup.
    local = write(tmp_path / "local.json", {"users": ["svc-db-07", "ADMIN_BACKUP"]})
    result = run(local)
    assert result.returncode == 1
    assert "users: admin_backup" in result.stderr


def test_empty_set_fails(tmp_path: Path) -> None:
    local = write(tmp_path / "local.json", {"users": [], "paths": []})
    result = run(local)
    assert result.returncode == 1
    assert "arms no canaries" in result.stderr


def test_public_set_is_not_empty() -> None:
    # Guard: if the public set were empty, every overlap check above would pass
    # vacuously.
    data = json.loads(PUBLIC.read_text(encoding="utf-8"))
    assert data["users"] and data["paths"]
