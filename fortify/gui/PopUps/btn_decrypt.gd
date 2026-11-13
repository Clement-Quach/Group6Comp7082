extends Button
@onready var tools: tool_main = get_node("/root/Main/ToolMain")
@onready var overwrite:CheckButton =$"../overwriteButton"
@onready var password:TextEdit = $"../password"

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.

func _on_pressed() -> void:
	
	if overwrite.button_pressed:
		GlobalLogger.InfoLog("decrypt in place pressed")
		tools.decrypt_in_place(password.text)
	else:
		GlobalLogger.InfoLog("decrypt and copy pressed")
		tools.decrypt(password.text)
		
