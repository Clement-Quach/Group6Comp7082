extends Node
class_name tool_main


@onready var virusCheck = virusCheckTool.new()
var fileDialog: FileDialog
@onready var gui = $"../Control"


func _ready() -> void:
	#attach as children
	add_child(virusCheck)
	
	
	fileDialog = FileDialog.new()
	add_child(fileDialog)

	fileDialog.file_mode = FileDialog.FILE_MODE_OPEN_FILE
	fileDialog.access = FileDialog.ACCESS_FILESYSTEM

func startFileDialog(filterArray: Array[String]) -> void:
	# Clear previously added filters
	fileDialog.filters.clear()

	for filter in filterArray:
		fileDialog.add_filter(filter)

	fileDialog.popup_centered(Vector2i(800, 600))

func checkForVirus() -> void:
	startFileDialog(["*.exe", "*.dll", "*.txt"])

	var path: String = await fileDialog.file_selected
	virusCheck.checkVirus(path)
	
func addFileAsVirus() -> void:
	startFileDialog(["*.exe", "*.dll", "*.txt"])

	var path: String = await fileDialog.file_selected
	virusCheck.addFileAsVirus(path)
	
func printToTerminal(string: String) ->void:
	gui.printToTerminal(string)
	pass
	
# dialog to chose a file to unlock
func restoreFile() -> void:
	startFileDialog(["*.quarantine"])

	var path: String = await fileDialog.file_selected
	virusCheck.unlockFile(path)
