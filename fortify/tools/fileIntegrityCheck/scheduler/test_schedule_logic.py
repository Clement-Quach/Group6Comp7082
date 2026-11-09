import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import schedule_logic as sl
from schedule_logic import ConfigError, due_run, latest_due, parse_schedule

# Reference calendar: 2026-11-09 is a Monday, 11-11 Wednesday, 11-13 Friday.


def sched(**over):
    data = {
        "integrity_check_enabled": True,
        "schedule_month": "All",
        "schedule_date": "Mon, Wed",
        "schedule_time_24h": "02:30",
        "godot_executable_path": "godot.exe",
        "log_file_path": "log.txt",
    }
    data.update(over)
    return parse_schedule(data)


def dt(y, mo, d, h=0, mi=0, s=0):
    return datetime(y, mo, d, h, mi, s)


class ParseTests(unittest.TestCase):
    def test_all_and_lists(self):
        s = sched(schedule_month="Jan, mar", schedule_date="Mon,Wed")
        self.assertEqual(s.months, {1, 3})
        self.assertEqual(s.weekdays, {0, 2})
        self.assertEqual(sched(schedule_month="All", schedule_date="all").months, set(range(1, 13)))

    def test_unknown_keys_ignored(self):
        sched(target_directory_to_scan="C:/old")  # must not raise

    def test_bad_values(self):
        for bad in (dict(schedule_month="Foo"), dict(schedule_date=""), dict(schedule_month=""),
                    dict(schedule_time_24h="25:00"), dict(schedule_time_24h="2pm")):
            with self.assertRaises(ConfigError, msg=bad):
                sched(**bad)


class LatestDueTests(unittest.TestCase):
    def test_before_and_after_time_same_day(self):
        s = sched()
        self.assertEqual(latest_due(s, dt(2026, 11, 9, 2, 30)), dt(2026, 11, 9, 2, 30))  # exact minute
        self.assertEqual(latest_due(s, dt(2026, 11, 9, 2, 29, 59)), dt(2026, 11, 4, 2, 30))  # prev Wed
        self.assertEqual(latest_due(s, dt(2026, 11, 9, 23, 0)), dt(2026, 11, 9, 2, 30))

    def test_non_matching_day_goes_back(self):
        self.assertEqual(latest_due(sched(), dt(2026, 11, 13, 12)), dt(2026, 11, 11, 2, 30))  # Fri -> Wed

    def test_month_filter_crosses_year(self):
        s = sched(schedule_month="Dec", schedule_date="All")
        self.assertEqual(latest_due(s, dt(2027, 2, 1, 12)), dt(2026, 12, 31, 2, 30))

    def test_midnight_boundary(self):
        s = sched(schedule_time_24h="00:00", schedule_date="All")
        self.assertEqual(latest_due(s, dt(2026, 11, 9, 0, 0)), dt(2026, 11, 9, 0, 0))


class DueRunTests(unittest.TestCase):
    def test_fires_once_when_time_reached(self):
        s = sched()
        last = dt(2026, 11, 9, 2, 0)
        self.assertIsNone(due_run(s, dt(2026, 11, 9, 2, 29, 59), last))
        self.assertEqual(due_run(s, dt(2026, 11, 9, 2, 30, 5), last), dt(2026, 11, 9, 2, 30))

    def test_no_repeat_after_run(self):
        s = sched()
        ran_at = dt(2026, 11, 9, 2, 30, 20)  # caller sets last_run = now after running
        for minute in (31, 45):
            self.assertIsNone(due_run(s, dt(2026, 11, 9, 2, minute), ran_at))
        self.assertIsNone(due_run(s, dt(2026, 11, 9, 23, 59), ran_at))

    def test_next_scheduled_day_fires_again(self):
        s = sched()
        self.assertIsNotNone(due_run(s, dt(2026, 11, 11, 2, 30), dt(2026, 11, 9, 2, 30, 20)))

    def test_many_missed_runs_collapse_to_one(self):
        # Daily schedule, monitor off for 9 days: exactly one catch-up, then nothing.
        s = sched(schedule_date="All")
        last = dt(2026, 11, 1, 2, 30, 10)
        now = dt(2026, 11, 10, 9, 0)
        due = due_run(s, now, last)
        self.assertEqual(due, dt(2026, 11, 10, 2, 30))
        self.assertIsNone(due_run(s, dt(2026, 11, 10, 9, 0, 30), now))  # last_run = now after catch-up
        self.assertIsNone(due_run(s, dt(2026, 11, 10, 23, 59), now))

    def test_missed_weekend_only_catches_up_once(self):
        s = sched()  # Mon, Wed
        last = dt(2026, 11, 4, 2, 30, 10)  # ran Wed
        self.assertEqual(due_run(s, dt(2026, 11, 13, 8), last), dt(2026, 11, 11, 2, 30))  # Mon+Wed missed

    def test_missed_but_nothing_due_in_between(self):
        s = sched()
        self.assertIsNone(due_run(s, dt(2026, 11, 10, 12), dt(2026, 11, 9, 2, 30, 20)))  # Tue

    def test_disabled(self):
        self.assertIsNone(due_run(sched(integrity_check_enabled=False), dt(2026, 11, 9, 3), dt(2026, 11, 1)))

    def test_no_history_means_no_run(self):
        self.assertIsNone(due_run(sched(), dt(2026, 11, 9, 3), None))

    def test_started_after_scheduled_time_does_not_fire_stale_run(self):
        s = sched()
        start = dt(2026, 11, 9, 8)  # first launch seeds last_run = start
        self.assertIsNone(due_run(s, dt(2026, 11, 9, 8, 1), start))


class FileTests(unittest.TestCase):
    def test_load_schedule_and_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "schedule.json"
            cfg.write_text(json.dumps({"schedule_time_24h": "04:15", "schedule_date": "All"}))
            self.assertEqual(sl.load_schedule(cfg).at.hour, 4)

            cfg.write_text("{not json")
            with self.assertRaises(ConfigError):
                sl.load_schedule(cfg)
            with self.assertRaises(ConfigError):
                sl.load_schedule(Path(tmp) / "missing.json")

            state = Path(tmp) / "sub" / "state.json"
            self.assertIsNone(sl.load_last_run(state))
            sl.save_last_run(state, dt(2026, 11, 9, 2, 30, 20))
            self.assertEqual(sl.load_last_run(state), dt(2026, 11, 9, 2, 30, 20))
            state.write_text("garbage")
            self.assertIsNone(sl.load_last_run(state))


if __name__ == "__main__":
    unittest.main()
