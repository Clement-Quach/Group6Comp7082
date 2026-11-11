extends Button
@onready var tools: tool_main = get_node("/root/Main/ToolMain")
@export var popup_scene: PackedScene
# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass


func _on_pressed() -> void:
	GlobalLogger.InfoLog("virusCheck popup pressed")
	var popup = popup_scene.instantiate()
	get_tree().root.add_child(popup)
	
