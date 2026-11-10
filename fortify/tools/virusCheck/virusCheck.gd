extends Node
class_name virusCheckTool

@onready var toolMain:tool_main = $".."
var database = virusDB.new()

## Extension that is added to files to lock them in windows
const EXT = ".quarantine"

## Saves file permissions for locked linux files
const INDEX_PATH = "user://quarantine_index.json"


func _init() -> void:
	var err := database.load_db()
	match err:
		OK:
			print("Loaded %d signatures" % database.size())
		ERR_FILE_NOT_FOUND:
			print("No database yet, starting empty")
		_:
			push_error("Failed to load DB: %s" % error_string(err))
	

func checkVirus(filepaths: PackedStringArray) -> void:
	for path in filepaths:
		# Check that the file exists
		if not FileAccess.file_exists(path):
			toolMain.printToTerminal("file not found: " + path + "\n")
			continue

		# Calculate the file's hash
		var hash := hash_file(path)

		# Check the virus database
		if database.lookup(hash):
			print("virus found: " + path)
			GlobalLogger.InfoLog("virus found")
			toolMain.printToTerminal("virus found: " + path + "\n")
			lockFile(path)
		else:
			print("virus false: " + path)
			GlobalLogger.InfoLog("virus found")
			toolMain.printToTerminal("virus false: " + path + "\n")
		
func addFileAsVirus(filepath: String) -> void:
	var err := database.add_file(filepath)
	if err == OK:
		print("added file")
	elif err == ERR_ALREADY_EXISTS:
		print("file was already in the database")
	else:
		push_error("failed to add file: %s" % error_string(err))
		return

	print("save_db returned: ", error_string(database.save_db()))

func hash_file(path: String) -> String:
	var data = FileAccess.get_file_as_bytes(path)

	var ctx = HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	if data.size() == 0:
		push_warning("FILE IS EMPTY. hash_file function: %s" % path)
		return "0"
	ctx.update(data)

	return ctx.finish().hex_encode()
	

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

func get_size():
	return database.size()

func get_last_update():
	return database.get_last_pull_time()


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------
# The download/import logic lives in virusDB. This is just a wrapper that also
# logs the outcome. NOTHING runs automatically, call it yourself and `await` it:
#
#     # last 48 hours of hashes (small, fast). This is the normal one to use.
#     var r: Dictionary = await virusCheckNode.pullFromMalwareBazaar()
#
#     # every hash ever (~3.5M, takes a while), optionally filtered by type
#     var r: Dictionary = await virusCheckNode.pullFromMalwareBazaar(true, PackedStringArray(["exe", "dll", "elf"]))
#
#     if r["error"] == OK: toolMain.printToTerminal(r["message"] + "\n")
#
# abuse.ch asks that "recent" is fetched at most every 5 minutes and "full" at
# most once per hour, so a pull inside those windows is refused with
# ERR_UNAVAILABLE. database.get_seconds_until_next_pull() and
# database.get_last_pull_string() tell you when you can pull again.

func pullFromMalwareBazaar(full: bool = false, file_types: PackedStringArray = PackedStringArray()) -> Dictionary:
	var result: Dictionary = await database.pull_from_malwarebazaar(self, full, file_types)
	if result["error"] == OK:
		GlobalLogger.InfoLog(result["message"])
	else:
		push_error(result["message"])
	return result
