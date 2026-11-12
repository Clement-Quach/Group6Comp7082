import json
import logging
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import integrity_scheduler as isch
import schedule_logic as sl

logging.disable(logging.CRITICAL)


def dt(d, h=0, mi=0, s=0):
    return datetime(2026, 11, d, h, mi, s)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cfg = self.dir / "schedule.json"
        self.state = self.dir / "state.json"
        self.calls = []
        self.exit_code = 0
        self.write_cfg()

    def tearDown(self):
        self.tmp.cleanup()

    def write_cfg(self, **over):
        data = {"integrity_check_enabled": True, "schedule_month": "All", "schedule_date": "All",
                "schedule_time_24h": "02:30", "godot_executable_path": "g.exe", "log_file_path": ""}
        data.update(over)
        self.cfg.write_text(json.dumps(data))

    def monitor(self):
        def runner(schedule):
            self.calls.append(schedule)
            return self.exit_code
        return isch.Monitor(self.cfg, self.state, self.dir, runner)

    def test_first_start_seeds_and_does_not_run(self):
        m = self.monitor()
        self.assertFalse(m.poll(dt(9, 8)))
        self.assertEqual(sl.load_last_run(self.state), dt(9, 8))
        self.assertEqual(self.calls, [])

    def test_runs_once_at_scheduled_time(self):
        m = self.monitor()
        m.poll(dt(9, 1))                        # seed
        self.assertFalse(m.poll(dt(9, 2, 29, 40)))
        self.assertTrue(m.poll(dt(9, 2, 30, 0)))
        self.assertFalse(m.poll(dt(9, 2, 30, 20)))
        self.assertFalse(m.poll(dt(9, 2, 31)))
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(m.poll(dt(10, 2, 30)))  # next day
        self.assertEqual(len(self.calls), 2)

    def test_catch_up_after_downtime_runs_once(self):
        sl.save_last_run(self.state, dt(1, 2, 30, 10))
        m = self.monitor()                      # restarted 9 days later
        self.assertTrue(m.poll(dt(10, 9)))
        self.assertFalse(m.poll(dt(10, 9, 0, 20)))
        self.assertEqual(len(self.calls), 1)

    def test_failed_run_not_retried_every_poll(self):
        self.exit_code = None
        m = self.monitor()
        m.poll(dt(9, 1))
        self.assertTrue(m.poll(dt(9, 2, 30)))
        self.assertFalse(m.poll(dt(9, 2, 30, 20)))
        self.assertEqual(len(self.calls), 1)

    def test_config_reload_and_errors(self):
        m = self.monitor()
        m.poll(dt(9, 1))
        self.write_cfg(schedule_time_24h="bogus")
        import os; os.utime(self.cfg, (1, 99999))   # ensure mtime changes
        self.assertFalse(m.poll(dt(9, 2, 30)))      # invalid -> keeps waiting, no crash
        self.assertEqual(self.calls, [])
        self.write_cfg(schedule_time_24h="02:30")
        os.utime(self.cfg, (1, 199999))
        self.assertTrue(m.poll(dt(9, 2, 31)))       # fixed config picked up

    def test_missing_config_does_not_crash(self):
        self.cfg.unlink()
        m = self.monitor()
        self.assertFalse(m.poll(dt(9, 3)))

    def test_disabled(self):
        self.write_cfg(integrity_check_enabled=False)
        m = self.monitor()
        m.poll(dt(9, 1))
        self.assertFalse(m.poll(dt(9, 2, 31)))


class CommandTests(unittest.TestCase):
    def test_build_command(self):
        s = sl.parse_schedule({"godot_executable_path": "C:/G/godot_console.exe", "log_file_path": "C:/L/x.log"})
        cmd = isch.build_command(s, Path("C:/proj"))
        self.assertEqual(cmd[0], "C:/G/godot_console.exe")
        self.assertIn("--headless", cmd)
        self.assertEqual(cmd[cmd.index("--script") + 1], isch.RUNNER_SCRIPT)
        self.assertEqual(cmd[cmd.index("--") + 1:], ["--trigger", "scheduled", "--log", "C:/L/x.log"])
        s2 = sl.parse_schedule({"godot_executable_path": "g"})
        self.assertNotIn("--log", isch.build_command(s2, Path("p")))

    def test_missing_exe_returns_none(self):
        s = sl.parse_schedule({"godot_executable_path": "Z:/nope/godot.exe"})
        self.assertIsNone(isch.run_godot(s, Path("."), 5))


class LockTests(unittest.TestCase):
    def test_second_instance_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.lock"
            first = isch.acquire_single_instance(p)
            self.assertIsNotNone(first)
            self.assertIsNone(isch.acquire_single_instance(p))
            first.close()


if __name__ == "__main__":
    unittest.main()
