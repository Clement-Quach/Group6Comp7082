extends Node

var file:FileAccess
var results:FileAccess
# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	create_log_file(file)
	create_log_file(results, "Results/")


func InfoLog(message: String):
	print("storing log")
	file.store_string(message)
	file.store_string("\n")
	
func errorLog(message:String):
	file.store_string(message)
	file.store_string("\n")

func resultLog(message:String):
	results.store_string(message)
	results.store_string("\n")

func create_log_file(file:FileAccess, name = "Log/") -> void:
	var date = Time.get_date_dict_from_system()

	var filename = "%04d-%02d-%02d.txt" % [
		date.year,
		date.month,
		date.day
	]

	file = FileAccess.open("res://" +name+ + filename, FileAccess.READ_WRITE)


	if file:
		print("log file found")
		file.seek_end()
	elif (file == null ):
		file = FileAccess.open("res://" +name+ + filename, FileAccess.WRITE)
		file.store_string("Created on: " + filename + "  \n")
		print("LOG created: ", filename)
	else:
		print("log file failed to load")
		push_error("log file failed to load")
