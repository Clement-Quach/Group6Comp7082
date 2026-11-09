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
	if not FileAccess.file_exists(path):
		return ERR_FILE_NOT_FOUND

	var data := FileAccess.get_file_as_bytes(path)

	var backup := FileAccess.open(
		path + ".bak",
		FileAccess.WRITE
	)

	if backup == null:
		return FileAccess.get_open_error()


	var compressed := data.compress(FileAccess.COMPRESSION_ZSTD)
	backup.store_32(data.size())
	backup.store_buffer(compressed)
	backup.close()

	return OK
	
##takes a normal file, finds its backup, and then overwrites the original
func restore_by_backup(path: String) -> Error:
	var backup_path := path + ".bak"

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

	var output := FileAccess.open(path, FileAccess.WRITE)
	if output == null:
		return FileAccess.get_open_error()

	output.store_buffer(data)
	output.close()
	return OK
	
## Takes a .bak file and restores the original file beside it.
func restore_from_backup(backup_path: String) -> Error:
	if not backup_path.ends_with(".bak"):
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

	var original_path := backup_path.trim_suffix(".bak")
	var output := FileAccess.open(original_path, FileAccess.WRITE)
	if output == null:
		return FileAccess.get_open_error()

	output.store_buffer(data)
	output.close()
	return OK
