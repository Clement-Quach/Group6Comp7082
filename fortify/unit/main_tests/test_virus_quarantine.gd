extends GutTest

var _quarantine: virusQuarantineTool
var _source_path := ""
var _locked_path := ""
var _index_path := ""
var _old_index_existed := false
var _old_index_contents := ""


func before_each() -> void:
	_quarantine = virusQuarantineTool.new()
	var unique := "gut_quarantine_%d_%d.txt" % [OS.get_process_id(), Time.get_ticks_usec()]
	_source_path = ProjectSettings.globalize_path("user://" + unique)
	_locked_path = _source_path + virusQuarantineTool.EXT
	_index_path = ProjectSettings.globalize_path(virusQuarantineTool.INDEX_PATH)
	_old_index_existed = FileAccess.file_exists(_index_path)
	if _old_index_existed:
		_old_index_contents = FileAccess.get_file_as_string(_index_path)


func after_each() -> void:
	if FileAccess.file_exists(_locked_path) and not FileAccess.file_exists(_source_path):
		_quarantine.unlockFile(_locked_path)
	_remove_absolute_file(_source_path)
	_remove_absolute_file(_locked_path)
	if _old_index_existed:
		var index_file := FileAccess.open(_index_path, FileAccess.WRITE)
		index_file.store_string(_old_index_contents)
		index_file.close()
	else:
		_remove_absolute_file(_index_path)
	_quarantine.free()


func test_lock_then_unlock_moves_file_and_preserves_contents() -> void:
	var contents := "quarantine fixture"
	var file := FileAccess.open(_source_path, FileAccess.WRITE)
	file.store_string(contents)
	file.close()

	assert_eq(_quarantine.lockFile(_source_path), OK)
	assert_false(FileAccess.file_exists(_source_path))
	assert_true(FileAccess.file_exists(_locked_path))
	assert_eq(_quarantine.lockFile(_source_path), ERR_ALREADY_EXISTS)

	assert_eq(_quarantine.unlockFile(_locked_path), OK)
	assert_true(FileAccess.file_exists(_source_path))
	assert_eq(FileAccess.get_file_as_string(_source_path), contents)


func _remove_absolute_file(path: String) -> void:
	if FileAccess.file_exists(path):
		DirAccess.remove_absolute(path)
