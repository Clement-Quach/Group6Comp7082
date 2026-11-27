# Copy this file into your Godot project as res://unit/test_tool_main.gd to run it.
# It tests tool_main's routing and decision logic with fake dependencies.
# The fakes prevent UI dialogs, network requests, and real file operations.

extends GutTest

const SAMPLE_FILE := "res://tests/sample.txt"
const SAMPLE_DIR := "res://tests"
const SAMPLE_BACKUP := "res://tests/sample.txt.bak_2026-01-01"
const SAMPLE_ENCRYPTED := "res://tests/sample.txt.fencrypt"


class FakeGui:
	extends Node
	var messages: Array[String] = []

	func printToTerminal(message: String) -> void:
		messages.append(message)


class FakeFileDialogManager:
	extends FileDialogManager
	var next_result: Dictionary = {"cancelled": true}
	var requests: Array = []
	var last_mode: int = -1
	var last_filters: Array = []

	func _ready() -> void:
		pass

	func openDialog(mode: FileDialog.FileMode, filterArray: Array[String] = []) -> Dictionary:
		last_mode = mode
		last_filters = filterArray.duplicate()
		requests.append({"mode": mode, "filters": last_filters.duplicate()})
		return next_result.duplicate(true)


class FakeAIManager:
	extends AIManager
	var ask_count := 0
	var report_count := 0
	var last_prompt := ""
	var last_report_input := ""
	var ask_response := "AI answer"
	var report_response := "Report body"

	func ask(prompt: String, _system_prompt: String = "") -> String:
		ask_count += 1
		last_prompt = prompt
		await get_tree().process_frame
		return ask_response

	func generateReport(log_text: String) -> String:
		report_count += 1
		last_report_input = log_text
		await get_tree().process_frame
		return report_response


class FakeBackupManager:
	extends fileBackupManager
	var calls: Array = []

	func create_backup(path: String) -> Error:
		calls.append({"method": "create_backup", "path": path})
		return OK

	func restore_by_backup(path: String) -> Error:
		calls.append({"method": "restore_by_backup", "path": path})
		return OK

	func restore_from_backup(path: String) -> Error:
		calls.append({"method": "restore_from_backup", "path": path})
		return OK


class FakeEncryptor:
	extends Encryptor
	var calls: Array = []

	func encrypt_file(path: String, password: String, output_path: String = "") -> Error:
		calls.append({"method": "encrypt", "path": path, "password": password, "output": output_path})
		return OK

	func decrypt_file(path: String, password: String, output_path: String = "") -> Error:
		calls.append({"method": "decrypt", "path": path, "password": password, "output": output_path})
		return OK


class FakeNetworkScanner:
	extends NetworkScanner
	var arp_result := "ARP results"
	var ports_result := "Port results"
	var arp_calls := 0
	var ports_calls := 0

	func get_arp_table() -> String:
		arp_calls += 1
		return arp_result

	func get_open_ports() -> String:
		ports_calls += 1
		return ports_result


class FakeVirusCheck:
	extends virusCheckTool
	var checked_file_sets: Array = []
	var checked_directories: Array[String] = []
	var added_files: Array[String] = []

	func checkVirus(paths: PackedStringArray) -> String:
		checked_file_sets.append(paths.duplicate())
		return "virus scan result"

	func checkDirectory(path: String) -> String:
		checked_directories.append(path)
		return "directory scan result"

	func addFileAsVirus(path: String) -> void:
		added_files.append(path)


class FakeVirusDatabase:
	extends virusDB
	var update_result: Dictionary = {"error": OK, "message": "Definitions ready"}
	var last_host: Node
	var last_force := true

	func update_official(host: Node, force: bool = false) -> Dictionary:
		last_host = host
		last_force = force
		await get_tree().process_frame
		return update_result


class FakeQuarantine:
	extends virusQuarantineTool
	var locked_files: Array[String] = []
	var restored_files: Array[String] = []

	func lockFile(path: String) -> Error:
		locked_files.append(path)
		return OK

	func unlockFile(path: String) -> Error:
		restored_files.append(path)
		return OK


var _host: Node
var _main: tool_main
var _gui: FakeGui
var _dialog: FakeFileDialogManager
var _ai: FakeAIManager
var _backup: FakeBackupManager
var _encryptor: FakeEncryptor
var _network: FakeNetworkScanner
var _virus_check: FakeVirusCheck
var _database: FakeVirusDatabase
var _quarantine: FakeQuarantine


func before_each() -> void:
	# tool_main expects Control beside it and FileDialogManager underneath it.
	# Build that small part of the scene tree so its @onready paths resolve.
	_host = Node.new()

	_gui = FakeGui.new()
	_gui.name = "Control"
	_host.add_child(_gui)

	_main = tool_main.new()
	_main.name = "tool_main"
	_host.add_child(_main)

	_dialog = FakeFileDialogManager.new()
	_dialog.name = "FileDialogManager"
	_main.add_child(_dialog)

	_ai = FakeAIManager.new()
	_backup = FakeBackupManager.new()
	_encryptor = FakeEncryptor.new()
	_network = FakeNetworkScanner.new()
	_virus_check = FakeVirusCheck.new()
	_database = FakeVirusDatabase.new()
	_quarantine = FakeQuarantine.new()
	for dependency in [_ai, _backup, _encryptor, _network, _virus_check, _database, _quarantine]:
		_main.add_child(dependency)

	_main.aiManager = _ai
	_main.fileBackup = _backup
	_main.encryptor = _encryptor
	_main.networkScanner = _network
	_main.virusCheck = _virus_check
	_main.virusDatabase = _database
	_main.virusQuarantine = _quarantine

	# Put Nodes in the scene tree. This triggers tool_main's @onready bindings.
	add_child(_host)


func after_each() -> void:
	if is_instance_valid(_host):
		_host.free()


func _select_file(path: String) -> void:
	_dialog.next_result = {"cancelled": false, "path": path}


func test_print_to_terminal_forwards_message_to_gui() -> void:
	_main.printToTerminal("hello")
	assert_eq(_gui.messages, ["hello"])


func test_check_for_virus_uses_selected_files_and_prints_results() -> void:
	var paths := PackedStringArray([SAMPLE_FILE, "res://tests/another.txt"])
	_dialog.next_result = {"cancelled": false, "paths": paths}

	await _main.checkForVirus()

	assert_eq(_dialog.last_mode, FileDialog.FILE_MODE_OPEN_FILES)
	assert_eq(_dialog.last_filters, ["*.exe", "*.dll", "*.txt"])
	assert_eq(_virus_check.checked_file_sets, [paths])
	assert_eq(_gui.messages.back(), "virus scan result")


func test_check_directory_scans_selected_directory_and_prints_results() -> void:
	_select_file(SAMPLE_DIR)

	await _main.checkDirForVirus()

	assert_eq(_dialog.last_mode, FileDialog.FILE_MODE_OPEN_DIR)
	assert_true(_dialog.last_filters.is_empty())
	assert_eq(_virus_check.checked_directories, [SAMPLE_DIR])
	assert_eq(_gui.messages.back(), "directory scan result")


func test_add_file_as_virus_forwards_selected_file() -> void:
	_select_file(SAMPLE_FILE)

	await _main.addFileAsVirus()

	assert_eq(_dialog.last_mode, FileDialog.FILE_MODE_OPEN_FILE)
	assert_eq(_dialog.last_filters, ["*.exe", "*.dll", "*.txt"])
	assert_eq(_virus_check.added_files, [SAMPLE_FILE])


func test_update_definitions_calls_database_and_reports_success_or_error() -> void:
	_database.update_result = {"error": OK, "message": "Definitions ready"}
	await _main.updateDefinitions()
	assert_eq(_database.last_host, _main)
	assert_false(_database.last_force)
	assert_eq(_gui.messages.back(), "Definitions ready\n")

	_database.update_result = {"error": ERR_CANT_CONNECT, "message": "offline"}
	await _main.updateDefinitions()
	assert_eq(_gui.messages.back(), "database update failed: offline\n")


func test_lock_and_restore_file_forward_selected_paths() -> void:
	_select_file(SAMPLE_FILE)
	await _main.lockFile()
	assert_eq(_quarantine.locked_files, [SAMPLE_FILE])

	_select_file("res://tests/sample.txt.quarantine")
	await _main.restoreFile()
	assert_eq(_quarantine.restored_files, ["res://tests/sample.txt.quarantine"])
	assert_eq(_dialog.last_filters, ["*.quarantine"])


func test_ask_ai_ignores_blank_prompt_and_displays_answer() -> void:
	await _main.askAI("   \n  ")
	assert_eq(_ai.ask_count, 0)
	assert_eq(_gui.messages.back(), "type a question first\n")

	await _main.askAI("Is this safe?")
	assert_eq(_ai.ask_count, 1)
	assert_eq(_ai.last_prompt, "Is this safe?")
	assert_eq(_gui.messages.back(), "AI: AI answer\n\n")


func test_generate_report_uses_scan_results_and_prints_report() -> void:
	await _main.generateReport()

	var expected := "Network Scan:\nARP results\n\nPort Scan:\nPort results"
	var actual := _ai.last_report_input

	var no_whitespace := RegEx.new()
	no_whitespace.compile("\\s+")

	expected = no_whitespace.sub(expected, "", true)
	actual = no_whitespace.sub(actual, "", true)

	assert_eq(actual, expected)


func test_backup_commands_forward_paths_and_reject_plain_bak_file() -> void:
	_select_file(SAMPLE_FILE)
	await _main.compressFile()
	assert_eq(_backup.calls.back(), {"method": "create_backup", "path": SAMPLE_FILE})

	_select_file("res://tests/old.bak")
	await _main.decompressFile()
	assert_eq(_gui.messages.back(), "Cannot select .bak files for this operation.\n")

	_select_file(SAMPLE_BACKUP)
	await _main.decompressFile()
	assert_eq(_backup.calls.back(), {"method": "restore_by_backup", "path": SAMPLE_BACKUP})

	_select_file(SAMPLE_BACKUP)
	await _main.unpackFile()
	assert_eq(_dialog.last_filters, ["*.bak_*"])
	assert_eq(_backup.calls.back(), {"method": "restore_from_backup", "path": SAMPLE_BACKUP})


func test_network_commands_and_full_scan_use_scanner_results() -> void:
	_main.networkScan()
	assert_eq(_gui.messages.back(), "ARP results")

	_main.portScan()
	assert_eq(_gui.messages.back(), "Port results")

	var result := _main.runFullScan()
	assert_eq(result, {"network": "ARP results", "ports": "Port results"})
	assert_eq(_network.arp_calls, 2)
	assert_eq(_network.ports_calls, 2)


func test_encryption_commands_forward_paths_passwords_and_output_names() -> void:
	_select_file(SAMPLE_FILE)
	await _main.encrypt("secret")
	assert_eq(_encryptor.calls.back(), {
		"method": "encrypt", "path": SAMPLE_FILE, "password": "secret", "output": SAMPLE_FILE + ".fencrypt"
	})

	_select_file(SAMPLE_ENCRYPTED)
	await _main.decrypt("secret")
	assert_eq(_encryptor.calls.back(), {
		"method": "decrypt", "path": SAMPLE_ENCRYPTED, "password": "secret", "output": SAMPLE_ENCRYPTED + ".dat"
	})

	_select_file(SAMPLE_FILE)
	await _main.encrypt_in_place("secret")
	assert_eq(_encryptor.calls.back(), {
		"method": "encrypt", "path": SAMPLE_FILE, "password": "secret", "output": ""
	})

	_select_file(SAMPLE_ENCRYPTED)
	await _main.decrypt_in_place("secret")
	assert_eq(_encryptor.calls.back(), {
		"method": "decrypt", "path": SAMPLE_ENCRYPTED, "password": "secret", "output": ""
	})


func test_cancelled_dialogs_skip_work() -> void:
	_dialog.next_result = {"cancelled": true}

	await _main.checkForVirus()
	await _main.checkDirForVirus()
	await _main.addFileAsVirus()
	await _main.lockFile()
	await _main.restoreFile()
	await _main.compressFile()
	await _main.decompressFile()
	await _main.unpackFile()
	await _main.encrypt("secret")
	await _main.decrypt("secret")
	await _main.encrypt_in_place("secret")
	await _main.decrypt_in_place("secret")

	assert_true(_virus_check.checked_file_sets.is_empty())
	assert_true(_virus_check.checked_directories.is_empty())
	assert_true(_virus_check.added_files.is_empty())
	assert_true(_quarantine.locked_files.is_empty())
	assert_true(_quarantine.restored_files.is_empty())
	assert_true(_backup.calls.is_empty())
	assert_true(_encryptor.calls.is_empty())
	assert_eq(_gui.messages, ["file backup cancelled"])
