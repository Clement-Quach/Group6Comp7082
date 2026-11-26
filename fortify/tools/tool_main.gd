extends Node
class_name tool_main

@onready var gui = $"../Control"
@onready var fileDialogManager:FileDialogManager =$FileDialogManager

@export var aiManager:AIManager
@export var encryptor:Encryptor
@export var fileBackup:fileBackupManager
@export var networkScanner:NetworkScanner
@export var virusCheck:virusCheckTool
@export var virusDatabase:virusDB
@export var virusQuarantine:virusQuarantineTool




func printToTerminal(string: String) ->void:
	gui.printToTerminal(string)


#VIRUS CHECK SECTION START ============================
func checkForVirus() -> void:
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILES,
		["*.exe", "*.dll", "*.txt"]
	)

	if result["cancelled"]:
		return

	var paths: PackedStringArray = result["paths"]
	printToTerminal(virusCheck.checkVirus(paths))
	
func checkDirForVirus() -> void:
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_DIR
	)

	if result["cancelled"]:
		return

	var path: String = result["path"]
	printToTerminal(virusCheck.checkDirectory(path))
#VIRUS CHECK SECTION END ============================
	
#VIRUS DATABASE SECTION START ============================
func addFileAsVirus() -> void:
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE,
		["*.exe", "*.dll", "*.txt"]
	)

	if result["cancelled"]:
		return

	virusCheck.addFileAsVirus(result["path"]) # TODO change to virusDB
	

func updateDefinitions() -> void:
	printToTerminal("Attempting to pull definition updates\n")
	var r: Dictionary = await virusDatabase.update_official(self, false)
	if r["error"] != OK:
		GlobalLogger.InfoLog("database update failed: " + r["message"] + "\n")
		printToTerminal("database update failed: " + r["message"] + "\n")
	else:
		GlobalLogger.InfoLog(r["message"] + "\n")
		printToTerminal(r["message"] + "\n")
#VIRUS DATABASE SECTION END ============================

#VIRUS QUARANTINE SECTION START ============================
func lockFile() -> void:
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE,
		["*.exe", "*.dll", "*.txt"]
	)

	if result["cancelled"]:
		return

	virusQuarantine.lockFile(result["path"])

func restoreFile() -> void:
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE,
		["*.quarantine"]
	)

	if result["cancelled"]:
		return

	virusQuarantine.unlockFile(result["path"])
#VIRUS QUARANTINE SECTION END ============================


#AI SECTION START ========================
# sends the prompt to the ai manager, and prints the results
func askAI(prompt: String) -> void:
	if prompt.strip_edges().is_empty():
		printToTerminal("type a question first\n")
		return

	printToTerminal("you: " + prompt + "\nthinking...\n")
	var answer: String = await aiManager.ask(prompt)
	printToTerminal("AI: " + answer + "\n\n")
	
# runs the runFullScan 
# then sends the reuslts to the generateReport function of the aiManager
# then prints the ai generated to the terminal
func generateReport() -> void:
	var results: Dictionary = runFullScan()

	var scan_results := """
	Network Scan:
	%s

	Port Scan:
	%s
	""" % [results["network"], results["ports"]]

	scan_results = scan_results.strip_edges()

	var report = await aiManager.generateReport(scan_results)

	printToTerminal("--- Scan report ---\n" + report + "\n\n")

#FILE BACKUP SECTION START =======================
func compressFile():
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE
	)

	if result["cancelled"]:
		printToTerminal("file backup cancelled")
		return

	fileBackup.create_backup(result["path"])
	
#restores a file
func decompressFile():
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE
	)

	if result["cancelled"]:
		return

	var path: String = result["path"]

	if path.get_extension().to_lower() == "bak":
		printToTerminal("Cannot select .bak files for this operation.\n")
		return

	fileBackup.restore_by_backup(path)

#takes a backup and unzips it into a new copy of the backup. used for if you have a backup and no original
func unpackFile():
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE,
		["*.bak_*"]
	)

	if result["cancelled"]:
		return

	fileBackup.restore_from_backup(result["path"])


#FILE BACKUP SECTION END =========================

#NETWORK SCAN SECTION START
func networkScan():
	printToTerminal(networkScanner.get_arp_table())
	
func portScan():
	printToTerminal(networkScanner.get_open_ports())
	
# runs a full scan, including the network and port scans, to use for ai scan summary
func runFullScan() -> Dictionary:
	var port_results = networkScanner.get_open_ports()
	var network_results = networkScanner.get_arp_table()

	return {
		"network": network_results,
		"ports": port_results
	}

#NETWORK SCAN SECTION END


#ENCRYPTION SECTION START
func encrypt(password: String):
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE
	)

	if result["cancelled"]:
		return

	var path: String = result["path"]
	encryptor.encrypt_file(path, password, path + ".fencrypt")
	
func decrypt(password: String):
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE
	)

	if result["cancelled"]:
		return

	var path: String = result["path"]
	encryptor.decrypt_file(path, password, path + ".dat")

func encrypt_in_place(password: String):
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE
	)

	if result["cancelled"]:
		return

	encryptor.encrypt_file(result["path"], password)
func decrypt_in_place(password: String):
	var result: Dictionary = await fileDialogManager.openDialog(
		FileDialog.FILE_MODE_OPEN_FILE
	)

	if result["cancelled"]:
		return

	encryptor.decrypt_file(result["path"], password)
