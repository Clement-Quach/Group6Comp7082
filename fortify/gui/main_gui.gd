extends Control

@onready var label = $output

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass

func printToTerminal(input: String) -> void:
	var popup_terminal: TextEdit = find_popup_terminal(get_tree().root)
	if popup_terminal != null:
		print("printing to terminal: " + input)
		popup_terminal.text += input

	#print to main terminal regardless if you find the popup terminal or not
	label.text += "\n"
	label.text += input
	
func find_popup_terminal(node: Node) -> TextEdit:
	if node.name == "popupTerminal" and node is TextEdit:
		return node as TextEdit

	for child in node.get_children():
		var found := find_popup_terminal(child)
		if found != null:

			return found

	return null
