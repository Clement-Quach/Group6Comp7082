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
var _main: tool_main
var _manager: Encryptor
var _plain_path := ""
var _encrypted_path := ""
var _restored_path := ""


func before_each() -> void:
	var base := "user://gut_encrypt_%d_%d" % [OS.get_process_id(), Time.get_ticks_usec()]
	_plain_path = base + ".txt"
	_encrypted_path = base + ".encrypted"
	_restored_path = base + ".restored.txt"

	_host = Node.new()
	var gui := CaptureGui.new()
	gui.name = "Control"
	_host.add_child(gui)
	_main = tool_main.new()
	_host.add_child(_main)
	var dialog := NoUiFileDialogManager.new()
	dialog.name = "FileDialogManager"
	_main.add_child(dialog)
	_manager = Encryptor.new()
	_main.add_child(_manager)
	_main.encryptor = _manager
	add_child(_host)


func after_each() -> void:
	_remove_file(_plain_path)
	_remove_file(_encrypted_path)
	_remove_file(_restored_path)
	if is_instance_valid(_host):
		_host.free()


func test_encrypt_then_decrypt_restores_original_bytes() -> void:
	var original := "temporary encryption test data"
	var file := FileAccess.open(_plain_path, FileAccess.WRITE)
	file.store_string(original)
	file.close()

	assert_eq(_manager.encrypt_file(_plain_path, "test password", _encrypted_path), OK)
	assert_true(FileAccess.file_exists(_encrypted_path))
	assert_eq(_manager.decrypt_file(_encrypted_path, "test password", _restored_path), OK)
	assert_eq(FileAccess.get_file_as_string(_restored_path), original)


func _remove_file(path: String) -> void:
	if not path.is_empty() and FileAccess.file_exists(path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(path))
