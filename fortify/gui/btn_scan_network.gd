extends Button
@onready var tools:tool_main = get_node("/root/Main/ToolMain")

func _on_pressed() -> void:
	GlobalLogger.InfoLog("network scan pressed")
	tools.networkScan()
