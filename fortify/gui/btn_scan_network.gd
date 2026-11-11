extends Button
@onready var tools:tool_main = get_node("/root/Main/ToolMain")



# Called when the node enters the scene tree for the first time.



func _on_pressed() -> void:
	GlobalLogger.InfoLog("network scan pressed")
	tools.networkScan()
