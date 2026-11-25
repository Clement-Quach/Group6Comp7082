extends Button


# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	tooltip_text = "Back to the main page"


# Called every frame. 'delta' is the elapsed time since the previous frame.


func _on_pressed() -> void:
	get_parent().get_parent().queue_free()
