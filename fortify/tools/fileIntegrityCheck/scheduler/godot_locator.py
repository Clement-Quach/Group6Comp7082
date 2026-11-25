"""Finds a Godot executable that actually works, so the scheduler does not depend on one
machine-specific path in schedule.json.

Order of preference (first one that passes `--version` wins):
  1. the path configured in schedule.json
  2. GODOT_PATH environment variable
  3. godot / godot4 / *_console on PATH
  4. common install folders

On Windows every candidate is expanded to its folder-mates first: the *_console.exe build is
preferred (clean exit codes/output), then the candidate itself, then other Godot*.exe files.
A console wrapper whose real editor exe is missing fails the probe and is skipped.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

IS_WINDOWS = os.name == "nt"
_VERSION_RE = re.compile(r"\d+\.\d+")


def probe(exe: str | Path, timeout: int = 20) -> tuple[bool, str]:
    """Run `<exe> --version`. Returns (works, reason)."""
    try:
        proc = subprocess.run(
            [str(exe), "--version"], capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return False, f"--version timed out after {timeout}s"
    except OSError as e:
        return False, f"cannot start: {e}"
    out = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        first = out.splitlines()[0] if out else f"exit {proc.returncode}"
        return False, first
    # GUI-subsystem builds (Godot.exe) may print nothing when captured; exit 0 is enough then.
    if out and not _VERSION_RE.search(out):
        return False, f"unexpected --version output: {out.splitlines()[0]}"
    return True, out.splitlines()[0] if out else "ok"


def _is_godot_exe(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() == ".exe" and "godot" in p.name.lower()


def _expand(candidate: Path) -> list[Path]:
    """Windows: console builds in the same folder first, then the candidate, then other Godot exes."""
    if not IS_WINDOWS:
        return [candidate]
    folder = candidate.parent
    try:
        mates = sorted(p for p in folder.iterdir() if _is_godot_exe(p))
    except OSError:
        return [candidate]
    consoles = [p for p in mates if "console" in p.name.lower()]
    others = [p for p in mates if "console" not in p.name.lower()]
    return consoles + [candidate] + others


def _common_dirs() -> list[Path]:
    if IS_WINDOWS:
        roots = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                 os.environ.get("LOCALAPPDATA")]
        return [Path(r) / "Godot" for r in roots if r]
    home = Path.home()
    return [Path("/usr/bin"), Path("/usr/local/bin"), Path("/snap/bin"), home / ".local" / "bin", home / "bin"]


def candidate_list(configured: str, env: dict | None = None,
                   which: Callable[[str], str | None] = shutil.which) -> list[Path]:
    env = os.environ if env is None else env
    seeds: list[Path] = []
    if configured:
        seeds.append(Path(configured))
    if env.get("GODOT_PATH"):
        seeds.append(Path(env["GODOT_PATH"]))
    for name in ("godot", "godot4", "Godot_console", "godot_console"):
        found = which(name)
        if found:
            seeds.append(Path(found))
    for d in _common_dirs():
        if d.is_dir():
            if IS_WINDOWS:
                seeds.extend(p for p in sorted(d.iterdir()) if _is_godot_exe(p))
            else:
                seeds.extend(d / n for n in ("godot", "godot4") if (d / n).is_file())

    ordered: list[Path] = []
    seen: set[str] = set()
    for seed in seeds:
        # A configured path that does not exist still gets reported, but nothing is expanded from it.
        for c in (_expand(seed) if seed.is_file() else [seed]):
            key = os.path.normcase(str(c))
            if key not in seen:
                seen.add(key)
                ordered.append(c)
    return ordered


def resolve_godot(configured: str, env: dict | None = None,
                  which: Callable[[str], str | None] = shutil.which,
                  prober: Callable[[Path], tuple[bool, str]] = probe) -> tuple[Path | None, list[tuple[Path, str]]]:
    """Returns (working exe or None, [(candidate, why it was rejected), ...])."""
    rejected: list[tuple[Path, str]] = []
    for cand in candidate_list(configured, env, which):
        if not cand.is_file():
            rejected.append((cand, "file does not exist"))
            continue
        ok, reason = prober(cand)
        if ok:
            return cand, rejected
        rejected.append((cand, reason))
    return None, rejected
