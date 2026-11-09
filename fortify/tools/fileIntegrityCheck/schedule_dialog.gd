extends ConfirmationDialog

## Schedule editor.
## Writes res://tools/fileIntegrityCheck/scheduler/schedule.json — the bridge file between this module and the
## standalone Python checker.

const SCHEDULE_JSON_PATH := "res://tools/fileIntegrityCheck/scheduler/schedule.json"
const MONTHS := ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
const DAYS   := ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

var chk_enabled: CheckBox
var chk_month_all: CheckBox
var chk_day_all: CheckBox
var month_checks: Array[CheckBox] = []
var day_checks: Array[CheckBox] = []
var time_edit: LineEdit
var exe_path_edit: LineEdit
var log_path_edit: LineEdit
var error_label: Label

var _browse_mode := 0          # 0 = exe, 1 = log
var _file_dialog: FileDialog

func _ready() -> void:
	title = "Schedule Integrity Check"
	ok_button_text = "Save"
	size = Vector2i(640, 600)
	min_size = Vector2i(520, 460)
	confirmed.connect(_on_confirmed)
	about_to_popup.connect(_on_about_to_popup)
	_build_ui()
	_create_file_dialog()
	_load_existing()

# ───────────────────────── UI construction ─────────────────────────

func _build_ui() -> void:
	var root = VBoxContainer.new()
	root.add_theme_constant_override("separation", 8)
	add_child(root)

	# Enabled
	chk_enabled = CheckBox.new()
	chk_enabled.text = "Enable integrity check"
	chk_enabled.button_pressed = true
	root.add_child(chk_enabled)

	root.add_child(HSeparator.new())

	# Months
	var month_label = Label.new()
	month_label.text = "Months:"
	root.add_child(month_label)

	var month_grid = GridContainer.new()
	month_grid.columns = 7
	root.add_child(month_grid)

	chk_month_all = CheckBox.new()
	chk_month_all.text = "All"
	chk_month_all.button_pressed = true
	chk_month_all.toggled.connect(_on_month_all_toggled)
	month_grid.add_child(chk_month_all)

	for i in MONTHS.size():
		var cb = CheckBox.new()
		cb.text = MONTHS[i]
		cb.button_pressed = true
		cb.toggled.connect(_on_month_item_toggled)
		month_checks.append(cb)
		month_grid.add_child(cb)
		cb.disabled = true  # since "All" is on initially

	# Days
	var day_label = Label.new()
	day_label.text = "Days:"
	root.add_child(day_label)

	var day_grid = GridContainer.new()
	day_grid.columns = 8
	root.add_child(day_grid)

	chk_day_all = CheckBox.new()
	chk_day_all.text = "Every day"
	chk_day_all.button_pressed = true
	chk_day_all.toggled.connect(_on_day_all_toggled)
	day_grid.add_child(chk_day_all)

	for i in DAYS.size():
		var cb = CheckBox.new()
		cb.text = DAYS[i]
		cb.button_pressed = true
		cb.toggled.connect(_on_day_item_toggled)
		day_checks.append(cb)
		day_grid.add_child(cb)
		cb.disabled = true  # since "Every day" is on initially

	# Time
	var time_row = HBoxContainer.new()
	root.add_child(time_row)
	var time_label = Label.new()
	time_label.text = "Time (HH:MM 24h):"
	time_label.custom_minimum_size.x = 160
	time_row.add_child(time_label)
	time_edit = LineEdit.new()
	time_edit.placeholder_text = "02:30"
	time_edit.text = "02:30"
	time_edit.custom_minimum_size.x = 100
	time_row.add_child(time_edit)

	root.add_child(HSeparator.new())

	# Path rows
	exe_path_edit    = _add_path_row(root, "Godot executable path:",     _on_browse_exe)
	log_path_edit    = _add_path_row(root, "Log file path:",             _on_browse_log)

	# Inline error label
	error_label = Label.new()
	error_label.modulate = Color(1, 0.4, 0.4)
	error_label.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	error_label.visible = false
	root.add_child(error_label)

func _add_path_row(parent: VBoxContainer, label_text: String, browse_cb: Callable) -> LineEdit:
	var label = Label.new()
	label.text = label_text
	parent.add_child(label)

	var row = HBoxContainer.new()
	parent.add_child(row)

	var edit = LineEdit.new()
	edit.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	row.add_child(edit)

	var btn = Button.new()
	btn.text = "Browse..."
	btn.pressed.connect(browse_cb)
	row.add_child(btn)

	return edit

# ───────────────────────── Toggle logic ─────────────────────────

func _on_month_all_toggled(pressed: bool) -> void:
	for cb in month_checks:
		cb.button_pressed = pressed
		cb.disabled = pressed

func _on_month_item_toggled(_pressed: bool) -> void:
	chk_month_all.set_pressed_no_signal(_all_checked(month_checks))

func _on_day_all_toggled(pressed: bool) -> void:
	for cb in day_checks:
		cb.button_pressed = pressed
		cb.disabled = pressed

func _on_day_item_toggled(_pressed: bool) -> void:
	chk_day_all.set_pressed_no_signal(_all_checked(day_checks))

func _all_checked(checks: Array) -> bool:
	for cb in checks:
		if not cb.button_pressed:
			return false
	return true

# ───────────────────────── File browse ─────────────────────────

func _create_file_dialog() -> void:
	_file_dialog = FileDialog.new()
	_file_dialog.access = FileDialog.ACCESS_FILESYSTEM
	_file_dialog.use_native_dialog = true
	_file_dialog.file_selected.connect(_on_file_dialog_file)
	_file_dialog.dir_selected.connect(_on_file_dialog_dir)
	add_child(_file_dialog)

func _on_browse_exe() -> void:
	_browse_mode = 0
	_file_dialog.file_mode = FileDialog.FILE_MODE_OPEN_FILE
	_file_dialog.title = "Select executable"
	_file_dialog.popup_centered_ratio(0.6)

func _on_browse_log() -> void:
	_browse_mode = 1
	_file_dialog.file_mode = FileDialog.FILE_MODE_SAVE_FILE
	_file_dialog.title = "Select log file path"
	_file_dialog.popup_centered_ratio(0.6)

func _on_file_dialog_file(path: String) -> void:
	match _browse_mode:
		0: exe_path_edit.text = path
		1: log_path_edit.text = path

func _on_file_dialog_dir(_path: String) -> void:
	pass

# ───────────────────────── Load / save ─────────────────────────

func _on_about_to_popup() -> void:
	error_label.visible = false
	_load_existing()

func _load_existing() -> void:
	if not FileAccess.file_exists(SCHEDULE_JSON_PATH):
		return
	var f = FileAccess.open(SCHEDULE_JSON_PATH, FileAccess.READ)
	if f == null:
		return
	var data = JSON.parse_string(f.get_as_text())
	if data is Dictionary:
		_apply_to_ui(data)

func _apply_to_ui(data: Dictionary) -> void:
	chk_enabled.button_pressed = bool(data.get("integrity_check_enabled", true))

	# Months
	var month_str = str(data.get("schedule_month", "All"))
	if month_str == "All":
		chk_month_all.set_pressed_no_signal(true)
		_on_month_all_toggled(true)
	else:
		chk_month_all.set_pressed_no_signal(false)
		var sel = _strip_list(month_str.split(","))
		for i in MONTHS.size():
			month_checks[i].button_pressed = MONTHS[i] in sel
			month_checks[i].disabled = false
		chk_month_all.set_pressed_no_signal(_all_checked(month_checks))

	# Days
	var day_str = str(data.get("schedule_date", "All"))
	if day_str == "All":
		chk_day_all.set_pressed_no_signal(true)
		_on_day_all_toggled(true)
	else:
		chk_day_all.set_pressed_no_signal(false)
		var sel = _strip_list(day_str.split(","))
		for i in DAYS.size():
			day_checks[i].button_pressed = DAYS[i] in sel
			day_checks[i].disabled = false
		chk_day_all.set_pressed_no_signal(_all_checked(day_checks))

	time_edit.text      = str(data.get("schedule_time_24h", "02:30"))
	exe_path_edit.text  = str(data.get("godot_executable_path", ""))
	log_path_edit.text  = str(data.get("log_file_path", ""))

func _on_confirmed() -> void:
	if not _validate_and_show():
		call_deferred("popup_centered")   # dialog already closed → reopen
		return
	_write_json(_collect_data())
	print("Schedule saved to: ", ProjectSettings.globalize_path(SCHEDULE_JSON_PATH))

func _collect_data() -> Dictionary:
	return {
		"integrity_check_enabled": chk_enabled.button_pressed,
		"schedule_month": "All" if chk_month_all.button_pressed else _join_selected(month_checks, MONTHS),
		"schedule_date":  "All" if chk_day_all.button_pressed   else _join_selected(day_checks, DAYS),
		"schedule_time_24h": time_edit.text.strip_edges(),
		"godot_executable_path": exe_path_edit.text.strip_edges(),
		"log_file_path": log_path_edit.text.strip_edges(),
	}

func _write_json(payload: Dictionary) -> void:
	var f = FileAccess.open(SCHEDULE_JSON_PATH, FileAccess.WRITE)
	if f == null:
		push_error("Cannot write schedule.json: " + str(FileAccess.get_open_error()))
		return
	f.store_string(JSON.stringify(payload, "\t"))
	f.close()

# ───────────────────────── Validation / helpers ─────────────────────────

func _validate_and_show() -> bool:
	var err := ""
	if not _is_valid_time(time_edit.text.strip_edges()):
		err = "Time must be HH:MM in 24-hour format (e.g. 02:30)."
	elif exe_path_edit.text.strip_edges().is_empty():
		err = "Executable path is required."
	error_label.text = err
	error_label.visible = not err.is_empty()
	return err.is_empty()

func _is_valid_time(s: String) -> bool:
	var parts = s.split(":")
	if parts.size() != 2: return false
	if not (parts[0].is_valid_int() and parts[1].is_valid_int()): return false
	var h = int(parts[0]); var m = int(parts[1])
	return h >= 0 and h <= 23 and m >= 0 and m <= 59

func _join_selected(checks: Array, labels: Array) -> String:
	var parts: Array[String] = []
	for i in checks.size():
		if checks[i].button_pressed:
			parts.append(labels[i])
	return ", ".join(parts)

func _strip_list(arr: PackedStringArray) -> Array:
	var out: Array = []
	for s in arr:
		out.append(str(s).strip_edges())
	return out
