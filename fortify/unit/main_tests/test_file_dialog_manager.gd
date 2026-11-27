extends GutTest

var _manager: FileDialogManager
var _results: Array = []


func before_each() -> void:
	_manager = FileDialogManager.new()
	_results = []
	_manager.dialog_finished.connect(func(result: Dictionary) -> void: _results.append(result))


func after_each() -> void:
	_manager.free()


func test_file_selection_emits_single_path_result() -> void:
	_manager._on_file_selected("res://tests/sample.txt")
	assert_eq(_results, [{"cancelled": false, "path": "res://tests/sample.txt"}])


func test_multiple_file_selection_emits_path_array() -> void:
	var paths := PackedStringArray(["res://a.txt", "res://b.txt"])
	_manager._on_files_selected(paths)
	assert_eq(_results, [{"cancelled": false, "paths": paths}])


func test_directory_selection_emits_directory_path() -> void:
	_manager._on_dir_selected("res://tests")
	assert_eq(_results, [{"cancelled": false, "path": "res://tests"}])


func test_cancel_emits_cancelled_result() -> void:
	_manager._on_dialog_cancelled()
	assert_eq(_results, [{"cancelled": true}])
