extends Node
class_name virusCheckTool

@onready var toolMain:tool_main = $".."
var database = virusDB.new()

## extension that would be added to the virus file to lock them in windows
## It does not lock in linux but good for letting us know which ones are locked
const EXT = ".quarantine"

## saves the original permessions for linux files
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
	
# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass



<<<<<<< HEAD
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
			lockfile(path)
		else:
			print("virus false: " + path)
			GlobalLogger.InfoLog("virus found")
			toolMain.printToTerminal("virus false: " + path + "\n")
=======
func checkVirus(filepaths: String):
	# if the file is alreadt locked we can't read it, so it would fail on linux, threfore skip it
	if filepaths.ends_with(EXT):
		toolMain.printToTerminal("already locked " + filepaths + "\n")
		return
	
	#later on replace this with a method to actually get a file
	var hash = hash_file(filepaths)
	if database.lookup(hash) :
		print(" virus found " + filepaths)
		lockFile(filepaths)
		toolMain.printToTerminal("virus found " + filepaths + "\n")
		
	else:
		print("checkVirus False")
		toolMain.printToTerminal("virus false " + filepaths + "\n")
>>>>>>> 72cd83383cc8f9d4a1d3bc0b9bbc406d6b686efe
		
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
