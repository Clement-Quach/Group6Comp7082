extends Node
class_name virusCheckTool

@onready var toolMain:tool_main = $".."
@export var database:virusDB
@export var quarantine:virusQuarantineTool
var suspicionDetector := SuspiciousStringDetector.new()
var entropyDetector:= EntropyChecker.new()


func checkVirus(filepaths: PackedStringArray) -> String:
	var output:String = ""
	for path in filepaths:
		# Check that the file exists
		if not FileAccess.file_exists(path):
			toolMain.printToTerminal("file not found: " + path + "\n")
			output += "file not found: " + path + "\n"
			continue

		# Calculate the file's hash
		var file_hash := hash_file(path)

		# Whitelist -> user database -> official database (decided inside virusDB)
		var res := database.classify(file_hash)
		
		#Running heuristics section
		#check file suspicion
		var susRes := suspicionDetector.check_strings(path)
		#check entropy
		var entropyRes := entropyDetector.check_entropy(path)
		
		var msg:String
		match res["verdict"]:
			
			virusDB.Verdict.USER, virusDB.Verdict.OFFICIAL:
				var where: String = "your database" if res["verdict"] == virusDB.Verdict.USER else "official database"
				msg = "virus found: %s (%s, %s)" % [path, res["name"], where]
				print(msg)
				GlobalLogger.InfoLog(msg + "\n")
				output += msg
				quarantine.lockFile(path)
			virusDB.Verdict.WHITELISTED:
				print("virus false (whitelisted): " + path)
				GlobalLogger.InfoLog("virus false (whitelisted) " + path + "\n")
				toolMain.printToTerminal("virus false (whitelisted): " + path + "\n")
			_:
				print("virus false: " + path)
				GlobalLogger.InfoLog("virus false " + path + "\n")
				output +="virus false: " + path + "\n"
	
		output += susRes
		output += entropyRes
	GlobalLogger.resultLog(output)
	return output

func checkDirectory(directory: String) -> String:
	var output: String = ""

	var dir := DirAccess.open(directory)

	if dir == null:
		var msg := "failed to open directory: " + directory
		toolMain.printToTerminal(msg + "\n")
		return msg + "\n"

	dir.list_dir_begin()

	var file_name := dir.get_next()

	while file_name != "":
		# Skip hidden/system navigation entries
		if file_name == "." or file_name == "..":
			file_name = dir.get_next()
			continue

		var full_path := directory.path_join(file_name)

		# Recursively scan subdirectories
		if dir.current_is_dir():
			output += checkDirectory(full_path)
		else:
			output += checkVirus([full_path])

		file_name = dir.get_next()

	dir.list_dir_end()
	return output

## TODO: remove this function once hash function location gets sorted out
func addFileAsVirus(filepath: String) -> void:
	match database.add_user_hash(hash_file(filepath), "UserAdded." + filepath.get_file()):
		OK:
			print("added file to the user database")
		ERR_ALREADY_EXISTS:
			print("file was already in the user database")
		var err:
			push_error("failed to add file: %s" % error_string(err))


## Mark a file as safe, even if the official database says otherwise.
func whitelistFile(filepath: String) -> void:
	match database.add_whitelist_hash(hash_file(filepath), "Whitelisted." + filepath.get_file()):
		OK:
			print("added file to the whitelist")
		ERR_ALREADY_EXISTS:
			print("file was already whitelisted")
		var err:
			push_error("failed to whitelist file: %s" % error_string(err))

func removeUserHash(hex: String) -> bool:
	return database.remove_user_hash(hex)


func removeWhitelistHash(hex: String) -> bool:
	return database.remove_whitelist_hash(hex)


func hash_file(path: String) -> String:
	var data = FileAccess.get_file_as_bytes(path)

	var ctx = HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	if data.size() == 0:
		push_warning("FILE IS EMPTY. hash_file function: %s" % path)
		return "0"
	ctx.update(data)

	return ctx.finish().hex_encode()
