extends GutTest

const LoggerScript = preload("res://tools/LogController/logger.gd")

var _logger
var _folder := ""
var _info_path := ""
var _results_path := ""


func before_each() -> void:
	_folder = "gut_logger_%d_%d" % [OS.get_process_id(), Time.get_ticks_usec()]
	_logger = LoggerScript.new()
	_logger.file = _logger.create_log_file(_folder)
	_logger.results = _logger.create_log_file(_folder + "/Results")
	_info_path = _dated_path(_folder)
	_results_path = _dated_path(_folder + "/Results")


func after_each() -> void:
	if _logger.file != null:
		_logger.file.close()
	if _logger.results != null:
		_logger.results.close()
	_remove_file(_info_path)
	_remove_file(_results_path)
	_remove_dir("user://" + _folder + "/Results")
	_remove_dir("user://" + _folder)
	_logger.free()


func test_info_error_and_result_logs_are_written_to_their_files() -> void:
	_logger.InfoLog("info entry")
	_logger.ErrorLog("error entry")
	_logger.resultLog("result entry")
	_logger.file.close()
	_logger.results.close()
	_logger.file = null
	_logger.results = null

	var main_log := FileAccess.get_file_as_string(_info_path)
	var results_log := FileAccess.get_file_as_string(_results_path)
	assert_true(main_log.contains("info entry"))
	assert_true(main_log.contains("error entry"))
	assert_true(results_log.contains("result entry"))


func _dated_path(folder: String) -> String:
	var date := Time.get_date_dict_from_system()
	var filename := "%04d-%02d-%02d.txt" % [date.year, date.month, date.day]
	return "user://%s/%s" % [folder, filename]


func _remove_file(path: String) -> void:
	if not path.is_empty() and FileAccess.file_exists(path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(path))


func _remove_dir(path: String) -> void:
	var absolute := ProjectSettings.globalize_path(path)
	if DirAccess.dir_exists_absolute(absolute):
		DirAccess.remove_absolute(absolute)
