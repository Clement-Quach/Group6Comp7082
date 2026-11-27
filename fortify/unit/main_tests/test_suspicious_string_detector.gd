extends GutTest

var _detector: SuspiciousStringDetector
var _test_path := ""


func before_each() -> void:
	_detector = SuspiciousStringDetector.new()
	_test_path = "user://gut_suspicion_%d_%d.txt" % [OS.get_process_id(), Time.get_ticks_usec()]


func after_each() -> void:
	if FileAccess.file_exists(_test_path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(_test_path))


func test_scan_finds_case_insensitive_command_and_url_indicators() -> void:
	_write_text("POWERSHELL -ENC abc123 https://example.test/payload")

	var result := _detector.scan_file(_test_path)
	var categories: Array[String] = []
	for finding: Dictionary in result["findings"]:
		categories.append(finding["category"])

	assert_true(result["success"])
	assert_true(categories.has("Command Execution"))
	assert_true(categories.has("URL"))


func test_scan_of_missing_file_returns_error_without_success() -> void:
	var result := _detector.scan_file(_test_path)
	assert_false(result["success"])
	assert_eq(result["error"], "File does not exist.")
	assert_true(result["findings"].is_empty())


func test_scan_rejects_files_above_configured_size_limit() -> void:
	_detector.max_file_size_bytes = 2
	_write_text("larger than two bytes")

	var result := _detector.scan_file(_test_path)
	assert_false(result["success"])
	assert_eq(result["error"], "File exceeds the maximum scan size.")


func _write_text(contents: String) -> void:
	var file := FileAccess.open(_test_path, FileAccess.WRITE)
	file.store_string(contents)
	file.close()
