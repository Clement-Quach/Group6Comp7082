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
var _gui: CaptureGui
var _scanner: virusCheckTool
var _sample_path := ""


func before_each() -> void:
	_sample_path = "user://gut_virus_check_%d_%d.txt" % [OS.get_process_id(), Time.get_ticks_usec()]
	_host = Node.new()
	_gui = CaptureGui.new()
	_gui.name = "Control"
	_host.add_child(_gui)

	_main = tool_main.new()
	_host.add_child(_main)
	var dialog := NoUiFileDialogManager.new()
	dialog.name = "FileDialogManager"
	_main.add_child(dialog)
	_scanner = virusCheckTool.new()
	_main.add_child(_scanner)
	_main.virusCheck = _scanner
	add_child(_host)


func after_each() -> void:
	if FileAccess.file_exists(_sample_path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(_sample_path))
	if is_instance_valid(_host):
		_host.free()


func test_hash_file_matches_sha256_and_empty_file_returns_sentinel() -> void:
	_write_sample("known text")
	var context := HashingContext.new()
	context.start(HashingContext.HASH_SHA256)
	context.update("known text".to_utf8_buffer())
	var expected := context.finish().hex_encode()
	assert_eq(_scanner.hash_file(_sample_path), expected)

	_write_sample("")
	assert_eq(_scanner.hash_file(_sample_path), "0")


func test_check_virus_reports_missing_file_without_database_access() -> void:
	var missing := _sample_path + ".missing"
	var result := _scanner.checkVirus(PackedStringArray([missing]))
	assert_eq(result, "file not found: " + missing + "\n")
	assert_eq(_gui.messages, ["file not found: " + missing + "\n"])


func _write_sample(contents: String) -> void:
	var file := FileAccess.open(_sample_path, FileAccess.WRITE)
	file.store_string(contents)
	file.close()
