extends Node
class_name virusQuarantineTool

@export var database:virusDB

const EXT = ".quarantine"
const INDEX_PATH = "user://quarantine_index.json"

func lockFile(path: String) -> Error:
	var locked := path + EXT

	if FileAccess.file_exists(locked):
		return ERR_ALREADY_EXISTS

	if OS.get_name() != "Windows":
		var index := _load_index()
		index[locked] = FileAccess.get_unix_permissions(path)
		FileAccess.set_unix_permissions(path, 0)
		_save_index(index)

	var err := DirAccess.rename_absolute(path, locked)
	if err != OK:
		return err

	return OK

func unlockFile(path: String) -> Error:
	var original := path.trim_suffix(EXT)

	if FileAccess.file_exists(original):
		return ERR_ALREADY_EXISTS

	var err := DirAccess.rename_absolute(path, original)
	if err != OK:
		return err

	if OS.get_name() != "Windows":
		var index := _load_index()
		var perms := int(index.get(path, 420))
		FileAccess.set_unix_permissions(original, perms)
		index.erase(path)
		_save_index(index)

	return OK



func _load_index() -> Dictionary:
	if not FileAccess.file_exists(INDEX_PATH):
		return {}
	var data = JSON.parse_string(FileAccess.get_file_as_string(INDEX_PATH))
	return data if data is Dictionary else {}


func _save_index(index: Dictionary) -> void:
	var f := FileAccess.open(INDEX_PATH, FileAccess.WRITE)
	if f:
		f.store_string(JSON.stringify(index))
