extends Button

# 1. Constants belong at the top of the script
const FILE_INTEGRITY_DASHBOARD = preload("uid://dij2e7oct2wjy")

func _ready() -> void:
	# 2. Tell this button to trigger a function when it gets clicked
	pressed.connect(_on_button_pressed)

# 3. The custom function that runs when the click happens
func _on_button_pressed() -> void:
	# This line completely swaps the current screen to your File Integrity Dashboard
	get_tree().change_scene_to_packed(FILE_INTEGRITY_DASHBOARD)
