import json
import logging
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from unittest import mock

import godot_locator
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
        with mock.patch.object(isch.godot_locator, "resolve_godot", return_value=(None, [])):
            self.assertIsNone(isch.run_godot(s, Path("."), 5))

    def test_build_command_uses_resolved_exe(self):
        s = sl.parse_schedule({"godot_executable_path": "broken.exe"})
        self.assertEqual(isch.build_command(s, Path("p"), "good.exe")[0], "good.exe")


class GodotLocatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def touch(self, name):
        p = self.dir / name
        p.write_text("")
        return p

    def resolve(self, configured, working, env=None):
        """working = set of file names whose probe succeeds."""
        probed = []

        def prober(p):
            probed.append(p.name)
            return (p.name in working, "ok" if p.name in working else "broken")
        env = {} if env is None else env
        exe, rejected = godot_locator.resolve_godot(str(configured), env=env, which=lambda n: None, prober=prober)
        return exe, rejected, probed

    def test_configured_working_path_is_used(self):
        exe = self.touch("godot")
        with mock.patch.object(godot_locator, "IS_WINDOWS", False),              mock.patch.object(godot_locator, "_common_dirs", return_value=[]):
            got, rejected, _ = self.resolve(exe, {"godot"})
        self.assertEqual(got, exe)
        self.assertEqual(rejected, [])

    def test_windows_broken_console_wrapper_falls_back_to_godot_exe(self):
        wrapper = self.touch("Godot_v4.7.2-stable_win64_console.exe")   # real editor exe is missing
        editor = self.touch("Godot.exe")
        with mock.patch.object(godot_locator, "IS_WINDOWS", True),              mock.patch.object(godot_locator, "_common_dirs", return_value=[]):
            got, rejected, _ = self.resolve(wrapper, {"Godot.exe"})
        self.assertEqual(got, editor)
        self.assertEqual([p.name for p, _ in rejected], [wrapper.name])

    def test_windows_prefers_console_build_next_to_configured_editor(self):
        editor = self.touch("Godot.exe")
        console = self.touch("Godot_v4.7.2-stable_win64_console.exe")
        with mock.patch.object(godot_locator, "IS_WINDOWS", True),              mock.patch.object(godot_locator, "_common_dirs", return_value=[]):
            got, _, _ = self.resolve(editor, {"Godot.exe", console.name})
        self.assertEqual(got, console)

    def test_env_var_used_when_configured_missing(self):
        exe = self.touch("godot")
        with mock.patch.object(godot_locator, "IS_WINDOWS", False),              mock.patch.object(godot_locator, "_common_dirs", return_value=[]):
            got, rejected, _ = self.resolve(self.dir / "nope.exe", {"godot"}, env={"GODOT_PATH": str(exe)})
        self.assertEqual(got, exe)
        self.assertEqual(rejected[0][1], "file does not exist")

    def test_nothing_works_returns_none_with_reasons(self):
        exe = self.touch("godot")
        with mock.patch.object(godot_locator, "IS_WINDOWS", False),              mock.patch.object(godot_locator, "_common_dirs", return_value=[]):
            got, rejected, _ = self.resolve(exe, set())
        self.assertIsNone(got)
        self.assertEqual(rejected[0][1], "broken")


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
