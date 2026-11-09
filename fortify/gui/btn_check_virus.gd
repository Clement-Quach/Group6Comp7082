extends Button
@onready var tools: tool_main = get_node("/root/Main/ToolMain")

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass
func _on_pressed() -> void:
	GlobalLogger.InfoLog("file_backup_restore_button pressed")
	tools.checkForVirus()
