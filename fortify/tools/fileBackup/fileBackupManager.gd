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

	backup.store_buffer(
		data.compress(FileAccess.COMPRESSION_ZSTD)
	)
	backup.close()

	return OK
	
func restore_backup(path: String) -> Error:
	var backup_path := path + ".bak"

	if not FileAccess.file_exists(backup_path):
		return ERR_FILE_NOT_FOUND

	var compressed := FileAccess.get_file_as_bytes(backup_path)

	# Decompress the backup
	var data := compressed.decompress(
		-1,
		FileAccess.COMPRESSION_ZSTD
	)

	if data.is_empty():
		return ERR_FILE_CORRUPT

	var file := FileAccess.open(path, FileAccess.WRITE)

	if file == null:
		return FileAccess.get_open_error()

	file.store_buffer(data)
	file.close()

	return OK
