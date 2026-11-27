extends GutTest

var _checker: EntropyChecker
var _test_path := ""


func before_each() -> void:
	_checker = EntropyChecker.new()
	_test_path = "user://gut_entropy_%d_%d.bin" % [OS.get_process_id(), Time.get_ticks_usec()]


func after_each() -> void:
	_remove_test_file()


func test_entropy_is_zero_for_empty_and_repeated_bytes() -> void:
	var empty := PackedByteArray()
	var repeated := PackedByteArray()
	for _i in 64:
		repeated.append(7)

	assert_eq(_checker._calculate_entropy(empty), 0.0)
	assert_true(absf(_checker._calculate_entropy(repeated)) < 0.0001)


func test_each_possible_byte_has_eight_bits_of_entropy() -> void:
	var all_bytes := PackedByteArray()
	for byte_value in 256:
		all_bytes.append(byte_value)
	assert_true(absf(_checker._calculate_entropy(all_bytes) - 8.0) < 0.0001)


func test_entropy_thresholds_classify_low_medium_and_high() -> void:
	assert_eq(_checker._classify_entropy(5.99), "Low")
	assert_eq(_checker._classify_entropy(6.0), "Medium")
	assert_eq(_checker._classify_entropy(7.0), "High")


func test_analyze_empty_file_reports_empty_success() -> void:
	var file := FileAccess.open(_test_path, FileAccess.WRITE)
	file.close()

	var result := _checker.analyze_file(_test_path)

	assert_true(result["success"])
	assert_eq(result["file_size"], 0)
	assert_eq(result["entropy"], 0.0)
	assert_eq(result["entropy_level"], "Empty")


func _remove_test_file() -> void:
	if FileAccess.file_exists(_test_path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(_test_path))
