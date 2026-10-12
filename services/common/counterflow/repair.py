from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete

from .db import SessionLocal
from .models import Repair, RepairCheck
from .settings import settings


VULNERABLE_BLOCK = '''        if vulnerable:
            # LAB-ONLY: deliberately unsafe query for a controlled SQL injection demo.
            sql = f"SELECT id, name, public FROM products WHERE public = 1 AND name LIKE '%{q}%'"
            try:
                rows = connection.execute(sql).fetchall()
            except sqlite3.Error:
                raise HTTPException(status_code=400, detail="Search query rejected") from None
        else:
            rows = connection.execute(
                "SELECT id, name, public FROM products WHERE public = 1 AND name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
'''

SAFE_BLOCK = '''        rows = connection.execute(
            "SELECT id, name, public FROM products WHERE public = 1 AND name LIKE ?",
            (f"%{q}%",),
        ).fetchall()
'''


def _run(command: list[str], cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, shell=False)


def run_baseline(repair_id: str) -> None:
    """Create a labeled deterministic candidate in a temporary Git checkout and run fixed tests."""
    with SessionLocal() as db:
        repair = db.get(Repair, repair_id)
        if repair is None:
            return
        repair.status = "inspecting"
        db.commit()
    artifact_root = Path(settings.repair_artifact_dir).resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    artifact_dir = artifact_root / repair_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    log_lines: list[str] = []
    sandbox: Path | None = None
    try:
        configured = os.getenv("REPAIR_SOURCE_DIR")
        repo = Path(configured).resolve() if configured else Path(__file__).resolve().parents[3] / "services" / "lab-origin"
        source_main = repo / "app" / "main.py"
        source_tests = repo / "tests"
        if not source_main.is_file() or not source_tests.is_dir():
            raise FileNotFoundError("Reviewed lab-origin source mapping is incomplete")
        main_text = source_main.read_text(encoding="utf-8")
        if VULNERABLE_BLOCK not in main_text:
            raise ValueError("The reviewed vulnerable query anchor was not found; no files were changed")
        sandbox = Path(tempfile.mkdtemp(prefix="counterflow-repair-"))
        sandbox_origin = sandbox / "services" / "lab-origin"
        sandbox_origin.mkdir(parents=True)
        shutil.copytree(repo / "app", sandbox_origin / "app")
        shutil.copytree(source_tests, sandbox_origin / "tests")
        workspace_root = Path(__file__).resolve().parents[3]
        if (workspace_root / "pytest.ini").is_file():
            shutil.copyfile(workspace_root / "pytest.ini", sandbox / "pytest.ini")
        init = _run(["git", "init", "-b", "baseline"], sandbox)
        if init.returncode:
            raise RuntimeError("git init failed: " + init.stderr[-1000:])
        for args in (
            ["git", "config", "user.name", "CounterFlow Lab"],
            ["git", "config", "user.email", "counterflow-lab@localhost"],
            ["git", "add", "services/lab-origin/app/main.py", "services/lab-origin/tests"],
        ):
            result = _run(args, sandbox)
            if result.returncode:
                raise RuntimeError(f"{args[1]} failed: {result.stderr[-1000:]}")
        commit = _run(["git", "commit", "-m", "reviewed disposable origin baseline"], sandbox)
        if commit.returncode:
            raise RuntimeError("baseline commit failed: " + commit.stderr[-1000:])
        base_sha = _run(["git", "rev-parse", "HEAD"], sandbox).stdout.strip()
        branch = f"counterflow/fix-sqli-{repair_id[:8]}"
        checkout = _run(["git", "checkout", "-b", branch], sandbox)
        if checkout.returncode:
            raise RuntimeError("branch creation failed: " + checkout.stderr[-1000:])
        candidate = sandbox_origin / "app" / "main.py"
        candidate_text = candidate.read_text(encoding="utf-8").replace(VULNERABLE_BLOCK, SAFE_BLOCK, 1)
        candidate.write_text(candidate_text, encoding="utf-8", newline="\n")
        diff_check = _run(["git", "diff", "--check"], sandbox)
        diff = _run(["git", "diff", "--", "services/lab-origin/app/main.py"], sandbox)
        if not diff.stdout.strip() or diff.returncode:
            raise RuntimeError("Candidate diff is empty or invalid")
        diff_path = artifact_dir / "repair.diff"
        diff_path.write_text(diff.stdout, encoding="utf-8")
        log_lines.append(f"branch={branch}\nbase={base_sha}\n")
        log_lines.append("The candidate is deterministic and is not presented as model-generated.\n")
        log_lines.append("git diff --check:\n" + diff_check.stdout + diff_check.stderr)
        patch_test = _run(["python", "-m", "pytest", "-q", "-m", "safe_after_patch", "services/lab-origin/tests"], sandbox, timeout=90)
        safe_test_log = patch_test.stdout + patch_test.stderr
        log_lines.append("safe-after-patch regression:\n" + safe_test_log)
        suite_test = _run(["python", "-m", "pytest", "-q", "-m", "not baseline_only and not safe_after_patch", "services/lab-origin/tests"], sandbox, timeout=90)
        suite_log = suite_test.stdout + suite_test.stderr
        log_lines.append("normal-origin regression suite:\n" + suite_log)
        passed = diff_check.returncode == 0 and patch_test.returncode == 0 and suite_test.returncode == 0
        log_path = artifact_dir / "repair.log"
        log_path.write_text("\n".join(log_lines), encoding="utf-8")
        ended = datetime.now(timezone.utc)
        with SessionLocal() as db:
            repair = db.get(Repair, repair_id)
            if repair:
                db.execute(delete(RepairCheck).where(RepairCheck.repair_id == repair_id))
                repair.branch = branch
                repair.commit_base = base_sha
                repair.diff_summary = "Parameterized SQLite search query; candidate is deterministic baseline remediation, not AI-generated."
                repair.artifact_path = str(diff_path)
                repair.status = "awaiting_approval" if passed else "failed"
                for name, command, code, log_ref in (
                    ("git diff whitespace check", "git diff --check", diff_check.returncode, str(log_path)),
                    ("SQL injection and benign regression", "pytest -m safe_after_patch", patch_test.returncode, str(log_path)),
                    ("origin regression suite", "pytest -m not-baseline-only", suite_test.returncode, str(log_path)),
                ):
                    db.add(RepairCheck(
                        id=str(uuid.uuid4()), repair_id=repair_id, test_name=name,
                        command_reference=command, exit_code=code, started_at=started,
                        ended_at=ended, log_ref=log_ref, outcome="passed" if code == 0 else "failed",
                    ))
                db.commit()
    except Exception as exc:
        log_lines.append(f"repair_failed={type(exc).__name__}: {exc}")
        (artifact_dir / "repair.log").write_text("\n".join(log_lines), encoding="utf-8")
        with SessionLocal() as db:
            repair = db.get(Repair, repair_id)
            if repair:
                repair.status = "failed"
                repair.diff_summary = "No verified patch was proposed. See the recorded failure log."
                db.commit()
    finally:
        if sandbox is not None:
            shutil.rmtree(sandbox, ignore_errors=True)
