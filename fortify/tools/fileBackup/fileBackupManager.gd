extends Node

class_name fileBackupManager
@onready var toolMain:tool_main = $".."

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass
func create_backup(path: String) -> Error:
	print("create backup")
	if not FileAccess.file_exists(path):
		print("file not found for backup")
		return ERR_FILE_NOT_FOUND

	var data := FileAccess.get_file_as_bytes(path)
	if data == null:
		return ERR_INVALID_DATA
	var datetime := Time.get_datetime_string_from_system(false, true)

	# Replace colons with hyphens for filesystem compatibility
	datetime = datetime.replace(":", "-")
	var backup_path := path + ".bak_" + datetime
	var backup := FileAccess.open(
		backup_path,
		FileAccess.WRITE
	)

	if backup == null:
		toolMain.printToTerminal("backup failed to open")
		return FileAccess.get_open_error()


	var compressed := data.compress(FileAccess.COMPRESSION_ZSTD)
	backup.store_32(data.size())
	backup.store_buffer(compressed)
	backup.close()
	toolMain.printToTerminal("backup created for: " + path)
	
	return OK
	
##takes a normal file, finds its backup, and then overwrites the original
func restore_by_backup(path: String) -> Error:
	var directory := path.get_base_dir()
	var filename := path.get_file()

	var dir := DirAccess.open(directory)
	if dir == null:
		return ERR_CANT_OPEN

	dir.list_dir_begin()

	var newest_backup := ""
	var entry := dir.get_next()

	while entry != "":
		if entry.begins_with(filename + ".bak_"):
			if entry > newest_backup:
				newest_backup = entry

		entry = dir.get_next()

	dir.list_dir_end()

	if newest_backup == "":
		return ERR_FILE_NOT_FOUND

	return restore_from_backup(directory.path_join(newest_backup))
	
## Takes a .bak file and restores the original file beside it.
func restore_from_backup(backup_path: String) -> Error:
	if backup_path.find(".bak_") == -1:
		return ERR_INVALID_PARAMETER
	if not FileAccess.file_exists(backup_path):
		return ERR_FILE_NOT_FOUND

	var file := FileAccess.open(backup_path, FileAccess.READ)
	if file == null:
		return FileAccess.get_open_error()

	if file.get_length() < 4:
		file.close()
		return ERR_FILE_CORRUPT

	var original_size := file.get_32()
	var compressed := file.get_buffer(file.get_length() - 4)
	file.close()

	var data := compressed.decompress(
		original_size,
		FileAccess.COMPRESSION_ZSTD
	)

	if data.size() != original_size:
		return ERR_FILE_CORRUPT

	var marker := ".bak_"
	var index := backup_path.find(marker)

	if index == -1:
		return ERR_INVALID_PARAMETER

	var original_path := backup_path.substr(0, index)
	var output := FileAccess.open(original_path, FileAccess.WRITE)
	if output == null:
		return FileAccess.get_open_error()

	output.store_buffer(data)
	output.close()
	toolMain.printToTerminal("backup restored for: " + backup_path)
	return OK
