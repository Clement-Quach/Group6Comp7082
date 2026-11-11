extends Button
@onready var tools: tool_main = get_node("/root/Main/ToolMain")
@export var popup_scene: PackedScene

func _on_pressed() -> void:
	GlobalLogger.InfoLog("update definitions pressesd")
	tools.updateDefinitions()
