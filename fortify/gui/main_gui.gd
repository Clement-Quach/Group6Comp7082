extends Control

@onready var label = $output
@onready var sidebar: PanelContainer =$Sidebar
@onready var sidebar_toggle: Button = $SidebarToggle
var sidebar_open := false

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	
	sidebar_toggle.text = "☰"


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta: float) -> void:
	pass




func _on_sidebar_toggle_pressed() -> void:
	_toggle_sidebar()

func _toggle_sidebar() -> void:
	sidebar_open = !sidebar_open
	if sidebar_open:
		sidebar_toggle.text = "◀"
	else:
		sidebar_toggle.text = "☰"
	var tween = create_tween()
	tween.tween_property(
		sidebar,
		"position:x",
		0 if sidebar_open else -sidebar.size.x,
		0.25
	).set_trans(Tween.TRANS_CUBIC).set_ease(Tween.EASE_OUT)

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
