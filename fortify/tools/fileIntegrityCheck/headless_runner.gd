extends SceneTree

## Headless entry point used by the Python scheduler.
##
## Run:
##   godot --headless --path <project_dir> --script res://tools/fileIntegrityCheck/headless_runner.gd -- [--trigger scheduled] [--log <path>]
##
## Exit codes: 0 = all valid, 1 = tampered/missing files found, 2 = error.

const FileIntegrityManager = preload("res://tools/fileIntegrityCheck/file_integrity_manager.gd")
const IntegrityLogger = preload("res://tools/fileIntegrityCheck/integrity_logger.gd")

func _initialize() -> void:
	var trigger := "scheduled"
	var log_path := ""

	var args := OS.get_cmdline_user_args()
	var i := 0
	while i < args.size():
		match args[i]:
			"--trigger":
				if i + 1 < args.size():
					trigger = args[i + 1]
					i += 1
			"--log":
				if i + 1 < args.size():
					log_path = args[i + 1]
					i += 1
		i += 1

	var summary := FileIntegrityManager.run_full_check(trigger, log_path)
	quit(summary.exit_code)
