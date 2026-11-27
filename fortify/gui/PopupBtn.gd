extends Button
class_name PopupBtn
@onready var tools: tool_main = get_node("/root/Main/ToolMain")
@export var popup_scene: PackedScene
@export var onClickLog:String

func _ready() -> void:
	pressed.connect(_on_pressed)


func _on_pressed() -> void:
	GlobalLogger.InfoLog(onClickLog)
	
	#try to free old popup if its there
	GlobalLogger.InfoLog("deleting old popup")
	var old_pop_up = _find_popup(get_tree().root)
	if old_pop_up != null:
		old_pop_up.queue_free()
	#check if scene is there
	if popup_scene == null:
		GlobalLogger.ErrorLog("no scene to instantiate")
		return
	var popup = popup_scene.instantiate()
	#check if instantiate fails
	if popup == null:
		GlobalLogger.ErrorLog("Scene instantiate on popup failed")
		return
	
	get_tree().root.add_child(popup)
	popup.position = Vector2(200,0)

func _clear_popup()->void:
	pass

func _find_popup(node:Node)-> Node:
	if node.name == "PopUp":
		return node 

	for child in node.get_children():
		var found := _find_popup(child)
		if found != null:

			return found

	return null
	
