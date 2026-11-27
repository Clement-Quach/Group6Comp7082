extends Button


# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pressed.connect(_on_pressed)
# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass

func _on_pressed() -> void:
	var old_pop_up = _find_popup(get_tree().root)
	if old_pop_up != null:
		old_pop_up.queue_free()

func _find_popup(node:Node)-> Node:
	if node.name == "PopUp":
		return node 

	for child in node.get_children():
		var found := _find_popup(child)
		if found != null:

			return found

	return null
	
