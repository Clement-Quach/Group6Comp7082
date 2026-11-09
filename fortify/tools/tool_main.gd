extends Node
class_name tool_main

var fileDialog: FileDialog

@onready var virusCheck = virusCheckTool.new()
@onready var gui = $"../Control"
@onready var aiManager = AIManager.new()
@onready var fileBackup = fileBackupManager.new()

func _ready() -> void:
	#attach as children
	add_child(virusCheck)
	
	add_child(aiManager)
	
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
	
func startSingleFileDialog(filterArray: Array[String]) -> void:
	fileDialog.file_mode = FileDialog.FILE_MODE_OPEN_FILE
	startFileDialog(filterArray)
	
func startMultiFileDialog(filterArray: Array[String]) -> void:
	fileDialog.file_mode = FileDialog.FILE_MODE_OPEN_FILES
	startFileDialog(filterArray)
	
func startAnyFileDialog(filterArray: Array[String]) -> void:
	fileDialog.file_mode = FileDialog.FILE_MODE_OPEN_ANY
	startFileDialog(filterArray)
	
#VIRUS CHECK SECTION START ============================
func checkForVirus() -> void:
	startMultiFileDialog(["*.exe", "*.dll", "*.txt"])

	var path:PackedStringArray = await fileDialog.files_selected
	virusCheck.checkVirus(path)
	
func addFileAsVirus() -> void:
	startFileDialog(["*.exe", "*.dll", "*.txt"])

	var path: String = await fileDialog.file_selected
	virusCheck.addFileAsVirus(path)

# dialog to chose a file to unlock
func restoreFile() -> void:
	startFileDialog(["*.quarantine"])

	var path: String = await fileDialog.file_selected
	virusCheck.unlockFile(path)
#VIRUS CHECK SECTION END ============================
func printToTerminal(string: String) ->void:
	gui.printToTerminal(string)
	pass
	

# sends the prompt to the ai manager, and prints the results
func askAI(prompt: String) -> void:
	if prompt.strip_edges().is_empty():
		printToTerminal("type a question first\n")
		return

	printToTerminal("you: " + prompt + "\nthinking...\n")
	var answer: String = await aiManager.ask(prompt)
	printToTerminal("AI: " + answer + "\n\n")
	
	
#FILE BACKUP SECTION START =======================
func compressFile():
	startFileDialog([""])
	
	var path: String = await fileDialog.file_selected
	fileBackup.create_backup(path)
	
func decompressFile():
	startFileDialog([""])
	
	var path: String = await fileDialog.file_selected
	fileBackup.restore_by_backup(path)

func unpackFile():
	startFileDialog(["*.bak"])
	
	var path: String = await fileDialog.file_selected
	fileBackup.restore_from_backup(path)


#FILE BACKUP SECTION END =========================
