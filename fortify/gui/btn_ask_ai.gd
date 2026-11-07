extends Button
@onready var tools: tool_main = get_node("/root/Main/ToolMain")
@onready var input: LineEdit = $PromptInput

func _on_pressed() -> void:
	var prompt := input.text
	input.clear()
	tools.askAI(prompt)
