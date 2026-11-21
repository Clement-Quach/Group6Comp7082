extends Button
class_name PopupBtn
@onready var tools: tool_main = get_node("/root/Main/ToolMain")
@export var popup_scene: PackedScene
@export var onClickLog:String

func _ready() -> void:
	pressed.connect(_on_pressed)


func _on_pressed() -> void:
	GlobalLogger.InfoLog(onClickLog)
	var popup = popup_scene.instantiate()
	get_tree().root.add_child(popup)
	
