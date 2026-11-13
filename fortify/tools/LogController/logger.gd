extends Node

var file: FileAccess
var results: FileAccess

func _ready() -> void:
	file = create_log_file("Logs")
	results = create_log_file("Logs/Results")

func InfoLog(message: String) -> void:
	file.store_line(message)

func ErrorLog(message: String) -> void:
	file.store_line(message)

func resultLog(message: String) -> void:
	results.store_line(message)

func create_log_file(folder: String) -> FileAccess:
	var directory := "res://%s" % folder
	DirAccess.make_dir_recursive_absolute(
		ProjectSettings.globalize_path(directory)
	)

	var date := Time.get_date_dict_from_system()
	var filename := "%04d-%02d-%02d.txt" % [
		date.year, date.month, date.day
	]
	var path := "%s/%s" % [directory, filename]
	var existed := FileAccess.file_exists(path)
	var mode := FileAccess.READ_WRITE if existed else FileAccess.WRITE
	var log_file := FileAccess.open(path, mode)

	if log_file == null:
		push_error("Could not open log file: %s" % path)
		return null

	if existed:
		log_file.seek_end()
	else:
		log_file.store_line("Created on: " + filename)

	return log_file
