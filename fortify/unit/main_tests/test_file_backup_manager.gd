extends GutTest

class CaptureGui:
	extends Node
	var messages: Array[String] = []
	func printToTerminal(message: String) -> void:
		messages.append(message)


class NoUiFileDialogManager:
	extends FileDialogManager
	func _ready() -> void:
		pass


var _host: Node
var _manager: fileBackupManager
var _source_path := ""
var _backup_path := ""


func before_each() -> void:
	var base := "user://gut_backup_%d_%d.txt" % [OS.get_process_id(), Time.get_ticks_usec()]
	_source_path = base
	_backup_path = base + ".bak_manual"

	_host = Node.new()
	var gui := CaptureGui.new()
	gui.name = "Control"
	_host.add_child(gui)
	var main := tool_main.new()
	_host.add_child(main)
	var dialog := NoUiFileDialogManager.new()
	dialog.name = "FileDialogManager"
	main.add_child(dialog)
	_manager = fileBackupManager.new()
	main.add_child(_manager)
	main.fileBackup = _manager
	add_child(_host)


func after_each() -> void:
	_remove_file(_source_path)
	_remove_file(_backup_path)
	for created_backup in _find_backups():
		_remove_file(created_backup)
	if is_instance_valid(_host):
		_host.free()


func test_create_backup_and_restore_by_backup_round_trip() -> void:
	var original := "backup test content"
	var source := FileAccess.open(_source_path, FileAccess.WRITE)
	source.store_string(original)
	source.close()

	assert_eq(_manager.create_backup(_source_path), OK)
	var created_backups := _find_backups()
	assert_eq(created_backups.size(), 1)
	assert_true(FileAccess.file_exists(created_backups[0]))

	var changed := FileAccess.open(_source_path, FileAccess.WRITE)
	changed.store_string("changed")
	changed.close()
	assert_eq(_manager.restore_by_backup(_source_path), OK)
	assert_eq(FileAccess.get_file_as_string(_source_path), original)


func test_restore_from_backup_rejects_invalid_or_missing_paths() -> void:
	assert_eq(_manager.restore_from_backup(_source_path), ERR_INVALID_PARAMETER)
	assert_eq(_manager.restore_from_backup(_backup_path), ERR_FILE_NOT_FOUND)
	assert_eq(_manager.create_backup(_source_path + ".missing"), ERR_FILE_NOT_FOUND)


func _find_backups() -> Array[String]:
	var found: Array[String] = []
	var dir := DirAccess.open(_source_path.get_base_dir())
	if dir == null:
		return found
	dir.list_dir_begin()
	var entry := dir.get_next()
	while not entry.is_empty():
		if entry.begins_with(_source_path.get_file() + ".bak_"):
			found.append(_source_path.get_base_dir().path_join(entry))
		entry = dir.get_next()
	dir.list_dir_end()
	return found


func _remove_file(path: String) -> void:
	if not path.is_empty() and FileAccess.file_exists(path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(path))
