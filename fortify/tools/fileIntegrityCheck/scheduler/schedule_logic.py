"""Pure schedule logic for the file-integrity scheduler (no I/O besides config/state files).

Every function that needs "now" takes it as an argument, so tests can use a fake clock.
All datetimes are naive local times.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from pathlib import Path

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]  # index == datetime.weekday()

# Longest gap between two matching dates is < 1 year (a single month + single weekday).
_MAX_LOOKBACK_DAYS = 366


class ConfigError(ValueError):
    """schedule.json is missing a field or contains an invalid value."""


@dataclass(frozen=True)
class Schedule:
    enabled: bool
    months: frozenset[int]    # 1..12
    weekdays: frozenset[int]  # 0=Mon .. 6=Sun
    at: time
    godot_executable_path: str
    log_file_path: str


# ───────────────────────── parsing ─────────────────────────

def _parse_names(value: object, names: list[str], field: str) -> frozenset[int]:
    text = str(value).strip()
    if text.lower() == "all":
        return frozenset(range(len(names)))
    lookup = {n.lower(): i for i, n in enumerate(names)}
    result = set()
    for token in text.split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token not in lookup:
            raise ConfigError(f"{field}: unknown value {token!r} (expected 'All' or names like {names[0]}, {names[1]})")
        result.add(lookup[token])
    if not result:
        raise ConfigError(f"{field}: nothing selected")
    return frozenset(result)


def _parse_time(value: object) -> time:
    try:
        hh, mm = str(value).strip().split(":")
        return time(int(hh), int(mm))
    except (ValueError, TypeError):
        raise ConfigError(f"schedule_time_24h: {value!r} is not HH:MM (24h)") from None


def parse_schedule(data: dict) -> Schedule:
    """Build a Schedule from the schedule.json dict. Unknown keys are ignored."""
    months = _parse_names(data.get("schedule_month", "All"), MONTHS, "schedule_month")
    days = _parse_names(data.get("schedule_date", "All"), DAYS, "schedule_date")
    months = frozenset(i + 1 for i in months)
    return Schedule(
        enabled=bool(data.get("integrity_check_enabled", True)),
        months=months,
        weekdays=days,
        at=_parse_time(data.get("schedule_time_24h", "02:30")),
        godot_executable_path=str(data.get("godot_executable_path", "")).strip(),
        log_file_path=str(data.get("log_file_path", "")).strip(),
    )


def load_schedule(path: str | Path) -> Schedule:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"schedule file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise ConfigError(f"schedule file is not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ConfigError("schedule file must contain a JSON object")
    return parse_schedule(data)


# ───────────────────────── matching / catch-up ─────────────────────────

def latest_due(schedule: Schedule, now: datetime) -> datetime | None:
    """Most recent scheduled moment that is <= now, or None if there is none within a year."""
    day = now.date()
    for _ in range(_MAX_LOOKBACK_DAYS + 1):
        if day.month in schedule.months and day.weekday() in schedule.weekdays:
            candidate = datetime.combine(day, schedule.at)
            if candidate <= now:
                return candidate
        day -= timedelta(days=1)
    return None


def due_run(schedule: Schedule, now: datetime, last_run: datetime | None) -> datetime | None:
    """Return the scheduled moment that should trigger a run now, else None.

    Catch-up rule: however many scheduled moments were missed since `last_run`,
    only the single latest one is returned, so the caller runs exactly once and
    then sets last_run = now.

    last_run=None means "no history": nothing is due (the caller should seed
    last_run with the start time so a first launch does not fire a stale run).
    """
    if not schedule.enabled or last_run is None:
        return None
    due = latest_due(schedule, now)
    if due is not None and due > last_run:
        return due
    return None


# ───────────────────────── state file ─────────────────────────

def load_last_run(path: str | Path) -> datetime | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return datetime.fromisoformat(data["last_run"])
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        return None


def save_last_run(path: str | Path, when: datetime) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"last_run": when.isoformat(timespec="seconds")}, indent="\t"), encoding="utf-8")
