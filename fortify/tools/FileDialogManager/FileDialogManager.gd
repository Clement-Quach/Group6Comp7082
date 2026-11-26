extends Node
class_name FileDialogManager

var fileDialog: FileDialog

signal dialog_finished(result: Dictionary)

func _ready() -> void:
	fileDialog = FileDialog.new()
	add_child(fileDialog)

	fileDialog.access = FileDialog.ACCESS_FILESYSTEM

	# Connect signals 
	fileDialog.file_selected.connect(_on_file_selected)
	fileDialog.files_selected.connect(_on_files_selected)
	fileDialog.dir_selected.connect(_on_dir_selected)
	fileDialog.canceled.connect(_on_dialog_cancelled)


# Opens the dialog 
func openDialog(
	mode: FileDialog.FileMode,
	filterArray: Array[String] = []
) -> Dictionary:

	fileDialog.file_mode = mode
	fileDialog.filters.clear()

	for filter in filterArray:
		if filter != "":
			fileDialog.add_filter(filter)

	fileDialog.popup_centered(Vector2i(800, 600))

	# Wait for either selection or cancellation
	var result: Dictionary = await dialog_finished

	return result


# SINGLE FILE
func _on_file_selected(path: String) -> void:
	dialog_finished.emit({
		"cancelled": false,
		"path": path
	})


# MULTIPLE FILES
func _on_files_selected(paths: PackedStringArray) -> void:
	dialog_finished.emit({
		"cancelled": false,
		"paths": paths
	})


# DIRECTORY
func _on_dir_selected(path: String) -> void:
	dialog_finished.emit({
		"cancelled": false,
		"path": path
	})


# CANCEL
func _on_dialog_cancelled() -> void:
	dialog_finished.emit({
		"cancelled": true
	})
	print("dialog cancel")
