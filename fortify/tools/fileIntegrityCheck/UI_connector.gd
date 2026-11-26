extends Node

const HashGenerator = preload("res://tools/fileIntegrityCheck/hash_generator.gd")
const FileIntegrityManager = preload("res://tools/fileIntegrityCheck/file_integrity_manager.gd")

# --- ADDED THIS CONSTANT ----------------------
const MAIN_UI_SCENE = "res://main.tscn"
#-----------------------------------------------

@onready var results_tree: Tree = $VBoxContainer/VerificationResultsTree
@onready var dropdown_algorithm: OptionButton = $VBoxContainer/ActionToolbar/DropdownAlgorithm
@onready var file_dialog: FileDialog = $VBoxContainer/TargetSelectorDialog
@onready var btn_select_target: Button = $VBoxContainer/ActionToolbar/BtnSelectTarget
@onready var btn_add_file: Button = $VBoxContainer/ActionToolbar/BtnAddFile
@onready var btn_run_verification: Button = $VBoxContainer/ActionToolbar/BtnRunVerification
@onready var btn_sync_database: Button = $VBoxContainer/ActionToolbar/BtnSyncDatabase
@onready var btn_schedule: Button = $VBoxContainer/ActionToolbar/BtnSchedule
@onready var btn_back: Button = $VBoxContainer/ActionToolbar/BtnBack

const JSON_DB_PATH = "res://tools/fileIntegrityCheck/trusted_hashes.json"
const ScheduleDialogScene = preload("res://tools/fileIntegrityCheck/schedule_dialog.tscn")

# Created at runtime in _ready() (it is not a node in the dashboard scene)
var schedule_dialog: ConfirmationDialog

# Created at runtime next to the "Add File" button
var btn_add_folder: Button

# State to track what the FileDialog is currently being used for
enum DialogMode { ADD_FILE, ADD_FOLDER, SELECT_TARGET }
var current_dialog_mode: DialogMode = DialogMode.ADD_FILE

func _ready() -> void:
	# Setup File Dialog
	file_dialog.file_mode = FileDialog.FILE_MODE_OPEN_FILE
	file_dialog.access = FileDialog.ACCESS_FILESYSTEM
	file_dialog.file_selected.connect(_on_file_selected)
	file_dialog.dir_selected.connect(_on_dir_selected)
	
	# "Add Folder" button (not in the scene file): registers every file under a folder
	btn_add_folder = Button.new()
	btn_add_folder.text = "Add Folder"
	btn_add_folder.pressed.connect(_on_btn_add_folder_pressed)
	btn_add_file.get_parent().add_child(btn_add_folder)
	btn_add_file.get_parent().move_child(btn_add_folder, btn_add_file.get_index() + 1)
	
	# Convert any old absolute-path keys to portable project-relative keys
	FileIntegrityManager.migrate_database()
	
	# Connect UI Buttons (Assuming they weren't connected in the editor)
	if not btn_add_file.pressed.is_connected(_on_btn_add_file_pressed):
		btn_add_file.pressed.connect(_on_btn_add_file_pressed)
	if not btn_select_target.pressed.is_connected(_on_btn_select_target_pressed):
		btn_select_target.pressed.connect(_on_btn_select_target_pressed)
	if not btn_run_verification.pressed.is_connected(_on_btn_run_verification_pressed):
		btn_run_verification.pressed.connect(_on_btn_run_verification_pressed)
	if not btn_sync_database.pressed.is_connected(_on_btn_sync_database_pressed):
		btn_sync_database.pressed.connect(_on_btn_sync_database_pressed)
	if not btn_schedule.pressed.is_connected(_on_btn_schedule_pressed):
		btn_schedule.pressed.connect(_on_btn_schedule_pressed)
	if not btn_back.pressed.is_connected(_on_btn_back_pressed):
		btn_back.pressed.connect(_on_btn_back_pressed)
		
	# Create the schedule dialog
	schedule_dialog = ScheduleDialogScene.instantiate()
	add_child(schedule_dialog)

	# Initialize the Tree
	_setup_tree()
	

func _setup_tree() -> void:
	results_tree.columns = 3
	results_tree.set_column_title(0, "File Path")
	results_tree.set_column_title(1, "Status")
	results_tree.set_column_title(2, "Hash / Details")
	results_tree.column_titles_visible = true
	
	# Create a hidden root item if it doesn't exist
	if not results_tree.get_root():
		results_tree.create_item()
		
	print("=== HashingContext availability test ===")
	for type_name in ["HASH_MD5", "HASH_SHA1", "HASH_SHA256"]:
		var ctx = HashingContext.new()
		var hash_type = HashingContext[type_name]
		var err = ctx.start(hash_type)
		print(type_name, " -> Error code: ", err, " (0 means available)")

# --- BUTTON HANDLERS ---

func _on_btn_add_file_pressed() -> void:
	current_dialog_mode = DialogMode.ADD_FILE
	file_dialog.file_mode = FileDialog.FILE_MODE_OPEN_FILE
	file_dialog.popup_centered(Vector2(600, 400))

func _on_btn_add_folder_pressed() -> void:
	current_dialog_mode = DialogMode.ADD_FOLDER
	file_dialog.file_mode = FileDialog.FILE_MODE_OPEN_DIR
	file_dialog.popup_centered(Vector2(600, 400))

func _on_btn_select_target_pressed() -> void:
	current_dialog_mode = DialogMode.SELECT_TARGET
	file_dialog.file_mode = FileDialog.FILE_MODE_OPEN_FILE
	file_dialog.popup_centered(Vector2(600, 400))

func _on_btn_run_verification_pressed() -> void:
	# For a simple demo, we verify all files currently listed in the JSON database
	if not FileIntegrityManager.database_exists():
		print("No database found to verify.")
		return
		
	results_tree.clear()
	_setup_tree() # Re-create root after clear

	# Shared with the headless scheduler run; uses each record's stored algorithm and writes the integrity log.
	var summary = FileIntegrityManager.run_full_check("manual")
	for entry in summary.entries:
		var result = entry.result
		var status_text = ""
		var color = Color.WHITE

		match result.status:
			FileIntegrityManager.VerificationStatus.VALID:
				status_text = "VALID"
				color = Color.GREEN
			FileIntegrityManager.VerificationStatus.TAMPERED:
				status_text = "TAMPERED"
				color = Color.RED
			FileIntegrityManager.VerificationStatus.MISSING_TRUSTED_HASH:
				status_text = "MISSING/UNREADABLE"
				color = Color.ORANGE

		_add_tree_row(entry.path, status_text, result.computed_hash, color)

func _on_btn_sync_database_pressed() -> void:
	# "Sync" usually means re-hashing trusted files to update the DB if they changed legitimately.
	# For this demo, we will just print the contents of both databases to the console.
	print("--- Current Trusted Hash Database (project + local) ---")
	if FileIntegrityManager.database_exists():
		print(JSON.stringify(FileIntegrityManager.load_database(), "	"))
	else:
		print("Database is empty.")
		
	_add_tree_row("SYSTEM", "SYNCED", "Database contents printed to console", Color.CYAN)

func _on_btn_back_pressed() -> void:
	if ResourceLoader.exists(MAIN_UI_SCENE):
		get_tree().change_scene_to_file(MAIN_UI_SCENE)
	else:
		push_error("Could not find main UI scene at: " + MAIN_UI_SCENE)

# --- DIALOG & DATA LOGIC ---

func _on_file_selected(path: String) -> void:
	if current_dialog_mode == DialogMode.ADD_FILE:
		add_file_to_database(path)
	elif current_dialog_mode == DialogMode.SELECT_TARGET:
		# Immediately verify the single selected file
		var algo_name = _get_selected_algorithm()
		var result = FileIntegrityManager.verify_file(path, algo_name)
		
		var status_text = "VALID" if result.status == FileIntegrityManager.VerificationStatus.VALID else "TAMPERED/MISSING"
		var color = Color.GREEN if result.status == FileIntegrityManager.VerificationStatus.VALID else Color.RED
		
		_add_tree_row(path, status_text, result.computed_hash, color)

func _on_dir_selected(dir_path: String) -> void:
	if current_dialog_mode == DialogMode.ADD_FOLDER:
		add_folder_to_database(dir_path)

## Registers every file under dir_path (recursive) with one DB write.
func add_folder_to_database(dir_path: String) -> void:
	if dir_path.is_empty(): return
	var result = FileIntegrityManager.register_folder(dir_path, _get_selected_algorithm())
	for item in result.registered:
		_add_tree_row(item.key, "REGISTERED", item.hash, Color.LIGHT_BLUE)
	for path in result.failed:
		_add_tree_row(path, "FAILED", "Could not hash file", Color.ORANGE)
	_add_tree_row(dir_path, "FOLDER", "%d registered, %d failed" % [result.registered.size(), result.failed.size()], Color.CYAN)

func add_file_to_database(file_path: String) -> void:
	if file_path.is_empty(): return
		
	var algo_name = _get_selected_algorithm()
	var computed_hash = HashGenerator.generate_hash(file_path, algo_name)
	
	if computed_hash.is_empty():
		print("UI_Connector Error: Failed to generate hash.")
		return
		
	_save_json_record(file_path, algo_name, computed_hash)
	_add_tree_row(FileIntegrityManager.to_db_key(file_path), "REGISTERED", computed_hash, Color.LIGHT_BLUE)

func _get_selected_algorithm() -> String:
	if dropdown_algorithm and dropdown_algorithm.selected >= 0:
		var text = dropdown_algorithm.get_item_text(dropdown_algorithm.selected).to_lower()
		# Normalize text: "SHA-256" -> "sha256", "SHA-1" -> "sha1"
		text = text.replace("-", "").replace(" ", "")
		return text
	return "sha256"

func _save_json_record(file_path: String, algo: String, hash_value: String) -> void:
	var data = FileIntegrityManager.load_database()
	data[FileIntegrityManager.to_db_key(file_path)] = {
		"algorithm": algo,
		"expected_hash": hash_value,
		"last_updated": Time.get_datetime_string_from_system()
	}
	FileIntegrityManager.save_database(data)

func _add_tree_row(file_name: String, status: String, hash_val: String, text_color: Color = Color.WHITE) -> void:
	var root = results_tree.get_root()
	if not root: return
	
	var child_item = results_tree.create_item(root)
	child_item.set_text(0, file_name)
	child_item.set_text(1, status)
	child_item.set_text(2, hash_val)
	
	# Color the row for better UX
	for i in range(3):
		child_item.set_custom_color(i, text_color)

func _on_btn_schedule_pressed() -> void:
	schedule_dialog.popup_centered()
