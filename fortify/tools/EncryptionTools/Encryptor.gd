extends Node
class_name Encryptor
@onready var toolMain:tool_main = $".."
# Called when the node enters the scene tree for the first time.


func encrypt_file(path: String, password: String, output_path: String = "") -> Error:
	var input := FileAccess.open(path, FileAccess.READ)
	if input == null:
		return FileAccess.get_open_error()
	var data := input.get_buffer(input.get_length())
	input.close()

	var destination := output_path if not output_path.is_empty() else path
	var output := FileAccess.open_encrypted_with_pass(destination, FileAccess.WRITE, password)
	if output == null:
		return FileAccess.get_open_error()
	output.store_buffer(data)
	output.close()
	
	toolMain.printToTerminal("file encrypted: " + output_path)
	return OK


func decrypt_file(path: String, password: String, output_path: String = "") -> Error:
	var input := FileAccess.open_encrypted_with_pass(path, FileAccess.READ, password)
	if input == null:
		return FileAccess.get_open_error()
	var data := input.get_buffer(input.get_length())
	input.close()

	var destination := output_path if not output_path.is_empty() else path
	var output := FileAccess.open(destination, FileAccess.WRITE)
	if output == null:
		return FileAccess.get_open_error()
	output.store_buffer(data)
	output.close()
	
	toolMain.printToTerminal("file decrypted: " + output_path)
	return OK
