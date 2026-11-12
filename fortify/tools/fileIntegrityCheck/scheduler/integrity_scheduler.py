"""Stand-alone monitor: waits for the scheduled time in schedule.json, then runs the
Godot file-integrity check headlessly.

    python integrity_scheduler.py                       # defaults: schedule.json next to this file
    python integrity_scheduler.py --config X --project Y
    python integrity_scheduler.py --run-now             # run one check immediately and exit (debug)

Exit codes of the Godot runner: 0 = all valid, 1 = tampered/missing found, 2 = error.
The monitor's own events are written to <project>/Logs/integrity/scheduler.log.
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import subprocess
import sys
import time as time_mod
from datetime import datetime
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # allow launching from any working directory / in isolated mode
    sys.path.insert(0, str(HERE))

import schedule_logic as sl  # noqa: E402

DEFAULT_PROJECT = HERE.parents[2]          # .../fortify  (scheduler -> fileIntegrityCheck -> tools -> fortify)
RUNNER_SCRIPT = "res://tools/fileIntegrityCheck/headless_runner.gd"
EXIT_MEANING = {
    0: "all files valid",
    1: "tampered or missing files found - see the integrity log",
    2: "runner error (e.g. trusted hash database missing)",
}

log = logging.getLogger("integrity_scheduler")


# ───────────────────────── running Godot ─────────────────────────

def build_command(schedule: sl.Schedule, project_dir: Path) -> list[str]:
    cmd = [
        schedule.godot_executable_path,
        "--headless",
        "--path", str(project_dir),
        "--script", RUNNER_SCRIPT,
        "--", "--trigger", "scheduled",
    ]
    if schedule.log_file_path:
        cmd += ["--log", schedule.log_file_path]
    return cmd


def run_godot(schedule: sl.Schedule, project_dir: Path, timeout: int) -> int | None:
    """Run the headless check. Returns Godot's exit code, or None if it could not run."""
    exe = Path(schedule.godot_executable_path) if schedule.godot_executable_path else None
    if exe is None or not exe.is_file():
        log.error("Godot executable not found: %r (set it in the Schedule dialog)", schedule.godot_executable_path)
        return None
    if not (project_dir / "project.godot").is_file():
        log.error("Not a Godot project folder (no project.godot): %s", project_dir)
        return None
    if "console" not in exe.name.lower():
        log.warning("%s is not the *_console.exe build; exit code/output may be unavailable", exe.name)

    cmd = build_command(schedule, project_dir)
    log.info("Launching: %s", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        log.error("Godot did not finish within %ds and was killed", timeout)
        return None
    except OSError as e:
        log.error("Could not start Godot: %s", e)
        return None

    if proc.returncode not in (0, 1):
        tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-10:])
        log.error("Godot output (last lines):\n%s", tail)
    return proc.returncode


# ───────────────────────── monitor ─────────────────────────

class Monitor:
    def __init__(self, config_path: Path, state_path: Path, project_dir: Path,
                 runner: Callable[[sl.Schedule], int | None]):
        self.config_path = config_path
        self.state_path = state_path
        self.project_dir = project_dir
        self.runner = runner
        self.schedule: sl.Schedule | None = None
        self._config_mtime: float | None = None
        self._config_error: str | None = None
        self.last_run: datetime | None = sl.load_last_run(state_path)
        self.running = False  # guard against overlapping runs

    def _reload_config_if_changed(self) -> None:
        try:
            mtime = self.config_path.stat().st_mtime
        except OSError:
            if self._config_error != "missing":
                log.error("Schedule file not found: %s", self.config_path)
                self._config_error = "missing"
            self.schedule = None
            self._config_mtime = None
            return
        if mtime == self._config_mtime:
            return
        self._config_mtime = mtime
        try:
            self.schedule = sl.load_schedule(self.config_path)
            self._config_error = None
            s = self.schedule
            log.info("Schedule loaded: enabled=%s months=%s days=%s time=%s",
                     s.enabled, sorted(s.months), [sl.DAYS[d] for d in sorted(s.weekdays)], s.at.strftime("%H:%M"))
        except sl.ConfigError as e:
            self.schedule = None
            self._config_error = str(e)
            log.error("Invalid schedule, will keep waiting: %s", e)

    def poll(self, now: datetime) -> bool:
        """One tick. Returns True if a check was triggered."""
        self._reload_config_if_changed()
        if self.schedule is None or self.running:
            return False

        if self.last_run is None:
            # First ever start: don't fire a stale run, just begin tracking from now.
            self.last_run = now
            sl.save_last_run(self.state_path, now)
            log.info("No previous run recorded; tracking from %s", now.isoformat(timespec="seconds"))
            return False

        due = sl.due_run(self.schedule, now, self.last_run)
        if due is None:
            return False

        late = now - due
        log.info("Schedule due (%s, last run %s)%s", due.isoformat(timespec="minutes"),
                 self.last_run.isoformat(timespec="seconds"),
                 "" if late.total_seconds() < 120 else f" - catching up, {late} late; running once")
        self.running = True
        try:
            code = self.runner(self.schedule)
        finally:
            self.running = False
        # Record the attempt even on failure, so a broken setup doesn't retry every poll.
        self.last_run = now
        sl.save_last_run(self.state_path, now)

        if code is None:
            log.error("Integrity check did NOT run (see errors above); next attempt at the next scheduled time")
        elif code in (0, 1):
            (log.info if code == 0 else log.warning)("Integrity check finished: exit %d - %s", code, EXIT_MEANING[code])
        else:
            log.error("Integrity check failed: exit %d - %s", code, EXIT_MEANING.get(code, "unexpected"))
        return True


# ───────────────────────── single instance + logging ─────────────────────────

def acquire_single_instance(lock_path: Path):
    """Keep a locked file open for the life of the process; returns the handle or None if another monitor runs."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def setup_logging(log_path: Path, verbose: bool) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    if sys.stderr is not None:  # pythonw.exe has no console
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)


# ───────────────────────── main ─────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scheduled Godot file-integrity check monitor")
    ap.add_argument("--config", type=Path, default=HERE / "schedule.json", help="schedule.json written by the Godot dialog")
    ap.add_argument("--project", type=Path, default=DEFAULT_PROJECT, help="Godot project folder (contains project.godot)")
    ap.add_argument("--state", type=Path, default=None, help="last-run state file (default: next to --config)")
    ap.add_argument("--log", type=Path, default=None, help="monitor log (default: <project>/Logs/integrity/scheduler.log)")
    ap.add_argument("--poll", type=int, default=20, help="seconds between clock checks")
    ap.add_argument("--timeout", type=int, default=900, help="kill a Godot run after this many seconds")
    ap.add_argument("--run-now", action="store_true", help="run one check immediately and exit")
    ap.add_argument("--stop-after-run", action="store_true", help="exit after the first scheduled run (for testing)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    config = args.config.resolve()
    project = args.project.resolve()
    state = (args.state or config.with_name("scheduler_state.json")).resolve()
    setup_logging((args.log or project / "Logs" / "integrity" / "scheduler.log").resolve(), args.verbose)

    def runner(schedule: sl.Schedule) -> int | None:
        return run_godot(schedule, project, args.timeout)

    if args.run_now:
        try:
            schedule = sl.load_schedule(config)
        except sl.ConfigError as e:
            log.error("Cannot run: %s", e)
            return 2
        log.info("--run-now: running one check immediately")
        code = runner(schedule)
        return 2 if code is None else code

    lock = acquire_single_instance(state.with_name("scheduler.lock"))
    if lock is None:
        log.error("Another integrity scheduler is already running; exiting")
        return 3

    log.info("Scheduler started (pid %d). config=%s project=%s poll=%ds", os.getpid(), config, project, args.poll)
    monitor = Monitor(config, state, project, runner)
    try:
        while True:
            try:
                if monitor.poll(datetime.now()) and args.stop_after_run:
                    return 0
            except Exception:  # never let one bad tick kill the monitor
                log.exception("Unexpected error in scheduler loop; continuing")
            time_mod.sleep(args.poll)
    except KeyboardInterrupt:
        log.info("Scheduler stopped by user")
        return 0


if __name__ == "__main__":
    sys.exit(main())
