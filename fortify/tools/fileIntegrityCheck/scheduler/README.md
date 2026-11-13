# File Integrity Scheduler

A stand-alone Python monitor. It reads `schedule.json` (written by the **Schedule** dialog in the
Godot dashboard), waits for the scheduled time, then runs the file-integrity check by launching
Godot headless. It uses only the Python standard library.

```
Godot dialog --writes--> schedule.json <--reads-- integrity_scheduler.py --launches--> godot --headless
                                                                                         headless_runner.gd
```

## Files
| File | Purpose |
|---|---|
| `integrity_scheduler.py` | The monitor (run this) |
| `schedule_logic.py` | Schedule parsing, matching, catch-up rule |
| `schedule.json` | Settings from the Godot dialog |
| `scheduler_state.json` | Last-run time (auto-created) |
| `install_task.ps1` | Registers the monitor with Windows Task Scheduler |
| `test_*.py` | Unit tests: `python -m unittest` in this folder |

## Requirements
- Python 3.9+ on PATH.
- `godot_executable_path` in the dialog must be the Godot **console** build
  (`Godot_v4.x-stable_win64_console.exe`), not the game and not `main.tscn`.
- The Godot project must have been opened in the editor at least once (so `.godot/` exists).

## Run it manually
```powershell
python integrity_scheduler.py                 # wait for the schedule
python integrity_scheduler.py --run-now       # run one check right now, then exit (good for debugging)
python integrity_scheduler.py --config D:\path\schedule.json --project D:\path\fortify
```
It can be started from any folder. Stop with Ctrl+C.

## Behaviour
- Checks the clock every 20 s (`--poll`). Changes saved in the dialog are picked up automatically.
- **Catch-up:** if the PC was off or asleep at the scheduled time, it runs once when the monitor is
  back, no matter how many runs were missed.
- The first time it ever starts it does not run; it only begins tracking.
- Only one monitor can run at a time (a second one exits with code 3).
- A Godot run is killed after 15 min (`--timeout`).

## Logs
| Log | Written by | Location |
|---|---|---|
| Integrity results (VALID / TAMPERED / MISSING per file) | Godot | `Logs/integrity/integrity_YYYY-MM-DD.log`, or `log_file_path` from the dialog |
| Monitor events (started, due, launched, exit code, errors) | Python | `Logs/integrity/scheduler.log` (rotates at 1 MB, keeps 3) |

Godot exit codes: `0` all valid, `1` tampered/missing files found, `2` runner error.

## Auto-start at logon (Windows Task Scheduler)

### Option A - script (recommended)
In PowerShell, in this folder:
```powershell
.\install_task.ps1 -StartNow      # register + start now
.\install_task.ps1 -Uninstall     # remove it later
```
If scripts are blocked: `powershell -ExecutionPolicy Bypass -File .\install_task.ps1 -StartNow`

### Option B - by hand
1. Open **Task Scheduler** -> **Create Task...** (not "Basic Task").
2. **General:** name `FortifyIntegrityScheduler`; "Run only when user is logged on".
3. **Triggers -> New:** Begin the task **At log on** (your user).
4. **Actions -> New:** Start a program
   - Program: full path of `pythonw.exe` (find it with `where pythonw`)
   - Arguments: `"D:\...\scheduler\integrity_scheduler.py"`
   - Start in: the `scheduler` folder
5. **Conditions:** untick "Start the task only if the computer is on AC power".
6. **Settings:** untick "Stop the task if it runs longer than"; set "If the task is already running" to **Do not start a new instance**.

### Check it works
- Task Scheduler -> right-click the task -> **Run**, then look at `Logs/integrity/scheduler.log`
  for `Scheduler started` and `Schedule loaded`.
- Test end to end: set the dialog time 2-3 minutes ahead, Save, and wait. The scheduler log shows
  `Schedule due` and `Integrity check finished`; the integrity log shows the file results.

### Troubleshooting
| Symptom | Cause |
|---|---|
| `Godot executable not found` | Wrong path in the dialog |
| `Not a Godot project folder` | Pass `--project <folder with project.godot>` |
| `Another integrity scheduler is already running` | A monitor is already active (check Task Manager for `pythonw.exe`) |
| Nothing logged at the scheduled time | Monitor not running, check `integrity_check_enabled`, month/day selection, and the time format `HH:MM` |
