class_name IntegrityLogger
extends RefCounted

## Writes the file-integrity log (separate from the team's GlobalLogger).
## One file per day: res://Logs/integrity/integrity_YYYY-MM-DD.log
## Line format:  YYYY-MM-DD HH:MM:SS | EVENT | details

const LOG_DIR := "res://Logs/integrity/"

static func default_log_path() -> String:
	var d := Time.get_date_dict_from_system()
	return LOG_DIR + "integrity_%04d-%02d-%02d.log" % [d.year, d.month, d.day]

static func write_line(log_path: String, event: String, details: String) -> void:
	var line := "%s | %s | %s" % [_timestamp(), event.rpad(8), details]
	print(line)
	_append(log_path, line)

static func _timestamp() -> String:
	# "2026-11-08T02:30:01" -> "2026-11-08 02:30:01"
	return Time.get_datetime_string_from_system(false, true)

static func _append(log_path: String, line: String) -> void:
	var dir_path := log_path.get_base_dir()
	if not DirAccess.dir_exists_absolute(dir_path):
		DirAccess.make_dir_recursive_absolute(dir_path)

	var f: FileAccess
	if FileAccess.file_exists(log_path):
		f = FileAccess.open(log_path, FileAccess.READ_WRITE)
		if f:
			f.seek_end()
	else:
		f = FileAccess.open(log_path, FileAccess.WRITE)

	if f == null:
		push_error("IntegrityLogger: cannot open %s (error %d)" % [log_path, FileAccess.get_open_error()])
		return
	f.store_line(line)
	f.close()
