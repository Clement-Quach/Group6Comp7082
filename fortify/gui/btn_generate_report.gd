
extends Button

@onready var tools: tool_main = get_node("/root/Main/ToolMain")

func _on_pressed() -> void:
	disabled = true
	text = "Generating Report..."

	await tools.generateReport()

	text = "Generate Scan Report"
	disabled = false
