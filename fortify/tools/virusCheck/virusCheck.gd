extends Node
class_name virusCheckTool

@onready var toolMain:tool_main = $".."
var database = virusDB.new()
	
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
	
