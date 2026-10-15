extends Node
class_name virusCheckTool

@onready var toolMain:tool_main = $".."
var database = virusDB.new()

# extension that would be added to the virus file to lock them in windows
const EXT = ".quarantine"

	
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



func checkVirus(filepaths: String):
	#later on replace this with a method to actually get a file
	var hash = hash_file(filepaths)
	if database.lookup(hash) :
		print(" virus found " + filepaths)
		lockfile(filepaths)
		toolMain.printToTerminal("virus found " + filepaths + "\n")
		
	else:
		print("checkVirus False")
		toolMain.printToTerminal("virus false " + filepaths + "\n")
		
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
	ctx.update(data)

	return ctx.finish().hex_encode()
	

# locks a given file
func lockfile(path: String) -> void:
	
	if path.ends_with(EXT):
		toolMain.printToTerminal("already locked " + path + "\n")
		return
		
	# perform renaming virus file -> adding EXT to the end
	var err := DirAccess.rename_absolute(path, path + EXT)
	
	# checking if virus file renaming is successful
	if err == OK:
		toolMain.printToTerminal("locked " + path + EXT + "\n")
	else:
		toolMain.printToTerminal("lock failed (%s)\n" % error_string(err))
		

# unlocks a given file
func unlockFile(path: String) -> void:
	
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
	if err == OK:
		toolMain.printToTerminal("restored " + original + "\n")
	else:
		toolMain.printToTerminal("restore failed (%s)\n" % error_string(err))
