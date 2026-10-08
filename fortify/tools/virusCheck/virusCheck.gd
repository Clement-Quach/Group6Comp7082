extends Node
class_name virusCheckTool

var database = virusDB.new()

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass
func checkVirus():
	#later on replace this with a method to actually get a file
	var hash = hash_file("res://tests/test.txt")
	if database.checkDB(hash) :
		print("checkVirus true")
	else:
		print("checkVirus False")
	
func hash_file(path: String) -> String:
	var data = FileAccess.get_file_as_bytes(path)

	var ctx = HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(data)

	return ctx.finish().hex_encode()
