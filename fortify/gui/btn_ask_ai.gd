extends Button
@onready var tools:tool_main = $"../../ToolMain"
@onready var input: LineEdit = $PromptInput

func _on_pressed() -> void:
	var prompt := input.text
	input.clear()
	tools.askAI(prompt)
