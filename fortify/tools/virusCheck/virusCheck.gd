extends Node
class_name virusCheckTool

@onready var toolMain:tool_main = $".."
var database := virusDB.new()

## Extension that is added to files to lock them in windows
const EXT = ".quarantine"

## Saves file permissions for locked linux files
const INDEX_PATH = "user://quarantine_index.json"


func checkVirus(filepaths: PackedStringArray) -> void:
	for path in filepaths:
		# Check that the file exists
		if not FileAccess.file_exists(path):
			toolMain.printToTerminal("file not found: " + path + "\n")
			continue

		# Calculate the file's hash
		var file_hash := hash_file(path)

		# Whitelist -> user database -> official database (decided inside virusDB)
		var res := database.classify(file_hash)

		match res["verdict"]:
			virusDB.Verdict.USER, virusDB.Verdict.OFFICIAL:
				var where: String = "your database" if res["verdict"] == virusDB.Verdict.USER else "official database"
				var msg := "virus found: %s (%s, %s)" % [path, res["name"], where]
				print(msg)
				GlobalLogger.InfoLog(msg + "\n")
				GlobalLogger.resultLog(msg + "\n")
				toolMain.printToTerminal(msg + "\n")
				lockFile(path)
			virusDB.Verdict.WHITELISTED:
				print("virus false (whitelisted): " + path)
				GlobalLogger.InfoLog("virus false (whitelisted) " + path + "\n")
				GlobalLogger.resultLog("virus false (whitelisted) " + path + "\n")
				toolMain.printToTerminal("virus false (whitelisted): " + path + "\n")
			_:
				print("virus false: " + path)
				GlobalLogger.InfoLog("virus false " + path + "\n")
				GlobalLogger.resultLog("virus false, no hash hit " + path + "\n")
				toolMain.printToTerminal("virus false: " + path + "\n")


## Flag a file as malware (adds its hash to YOUR database).
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


## For false positives: restores a locked file AND whitelists it so it isn't
## locked again on the next scan. (The file must be readable again before it
## can be hashed, which is why unlockFile() runs first.)
func unlockAndWhitelist(path: String) -> void:
	unlockFile(path)
	var original := path.trim_suffix(EXT)
	if FileAccess.file_exists(original):
		whitelistFile(original)


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


# ---------------------------------------------------------------------------
# Locking / unlocking (unchanged)
# ---------------------------------------------------------------------------

## locks a given file
func lockFile(path: String) -> void:

	# if already locked
	if path.ends_with(EXT):
		toolMain.printToTerminal("already locked " + path + "\n")
		return

	# get the path of the locked file and intialize the permissions of the file
	var locked := path + EXT
	var perms := 0

	if OS.get_name() != "Windows":
		# remember the original permissions of the file
		perms = FileAccess.get_unix_permissions(path)

	# perform renaming virus file -> adding EXT to the end
	# this "lockes" the file windows and is just a visual indicator for linux that the file is locked
	var err := DirAccess.rename_absolute(path, locked)

	# checking if virus file renaming is successful
	if err != OK:
		toolMain.printToTerminal("lock failed (%s)\n" % error_string(err))
		return

	# actually locking the file for linux, by changing its permissions
	if OS.get_name() != "Windows":
		# like chmod 000
		FileAccess.set_unix_permissions(locked, 0)
		var index := _load_index()
		index[locked] = perms
		_save_index(index)

	toolMain.printToTerminal("locked " + locked + "\n")

## unlocks a given file
func unlockFile(path: String) -> void:

	## if file is already locked
	if not path.ends_with(EXT):
		toolMain.printToTerminal("not a locked file " + path + "\n")
		return

	# get the original name of file -> remove EXT
	var original := path.trim_suffix(EXT)

	# check if a file with the original name already exist
	if FileAccess.file_exists(original):
		toolMain.printToTerminal("can't restore, a file with that name exists\n")
		return

	# else rename it -> remove the EXT if a file with the original name does not exist
	var err := DirAccess.rename_absolute(path, original)
	if err != OK:
		toolMain.printToTerminal("restore failed (%s)\n" % error_string(err))
		return

	# change the permissions of the file to the original on linux
	if OS.get_name() != "Windows":
		var index := _load_index()
		# fall back to rw-r--r-- if we don't know the original permissions
		var perms := int(index.get(path, 420))
		FileAccess.set_unix_permissions(original, perms)
		index.erase(path)
		_save_index(index)

	toolMain.printToTerminal("restored " + original + "\n")


## load the saved permissions of the locked files
func _load_index() -> Dictionary:
	if not FileAccess.file_exists(INDEX_PATH):
		return {}
	var data = JSON.parse_string(FileAccess.get_file_as_string(INDEX_PATH))
	return data if data is Dictionary else {}

## save a permission of a file that has been locked into the json file
func _save_index(index: Dictionary) -> void:
	var f := FileAccess.open(INDEX_PATH, FileAccess.WRITE)
	if f:
		f.store_string(JSON.stringify(index))


# ---------------------------------------------------------------------------
# Info for the UI
# ---------------------------------------------------------------------------

## Signatures that can flag a file (official + user). Whitelist is separate.
func get_size() -> int:
	return database.size()

func get_official_size() -> int:
	return database.official_size()

func get_user_size() -> int:
	return database.user_size()

func get_whitelist_size() -> int:
	return database.whitelist_size()

## Unix time of the official database build that is installed (0 = none yet).
func get_last_update() -> int:
	return database.get_official_version()


# ---------------------------------------------------------------------------
# Official database updates (from GitHub)
# ---------------------------------------------------------------------------
# Runs on its own at startup and every UPDATE_CHECK_INTERVAL (see _ready).
# You can also call it yourself, e.g. from an "Update now" button:
#
#     var r: Dictionary = await virusCheckNode.updateOfficialDatabase()
#     var r: Dictionary = await virusCheckNode.updateOfficialDatabase(true)   # force re-download
#
# r = {error, message, updated, local_version, remote_version}

func updateOfficialDatabase(force: bool = true) -> Dictionary:
	var r: Dictionary = await database.update_official(self, force)
	if r["error"] != OK:
		GlobalLogger.InfoLog("database update failed: " + r["message"] + "\n")
		GlobalLogger.resultLog("virus hash database update failed: " + "\n")
		toolMain.printToTerminal("database update failed: " + r["message"] + "\n")
	else:
		GlobalLogger.InfoLog(r["message"] + "\n")
		GlobalLogger.resultLog("virus hash database success" + r["message"] + "\n")
		toolMain.printToTerminal(r["message"] + "\n")
	return r
