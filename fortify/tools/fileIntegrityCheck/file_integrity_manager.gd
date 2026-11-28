class_name FileIntegrityManager
extends RefCounted

const HashGenerator = preload("res://tools/fileIntegrityCheck/hash_generator.gd")
const IntegrityLogger = preload("res://tools/fileIntegrityCheck/integrity_logger.gd")

enum VerificationStatus {
	VALID,
	TAMPERED,
	MISSING_TRUSTED_HASH
}

class VerificationResult:
	var status: VerificationStatus
	var computed_hash: String
	var expected_hash: String
	var timestamp: int
	
	func _init(p_status: VerificationStatus, p_computed: String, p_expected: String) -> void:
		status = p_status
		computed_hash = p_computed
		expected_hash = p_expected
		timestamp = Time.get_unix_time_from_system()

## Project DB (DEBUG ONLY): "res://" records, shared via git. Only read/written in the
## editor or a debug build; in a release build it is ignored completely (res:// is
## read-only there). It may be missing or empty - that is never an error.
const JSON_DB_PATH = "res://tools/fileIntegrityCheck/trusted_hashes.json"
## Local DB (the real database in every build): lives in Godot's user data folder, per
## machine and per user, so it is never part of the repository. Holds absolute-path
## records and, in a release build, the "res://" records too.
const LOCAL_DB_PATH = "user://local_hashes.json"

## Tests can set this to true to behave like a release build.
static var force_release_mode := false

## True when the project DB (res://) may be used: editor or debug build only.
static func project_db_enabled() -> bool:
	return not force_release_mode and (OS.has_feature("editor") or OS.is_debug_build())

static func verify_file(file_path: String, algorithm_name: String = "sha256") -> VerificationResult:
	var computed_hash = HashGenerator.generate_hash(file_path, algorithm_name)
	if computed_hash.is_empty():
		return VerificationResult.new(VerificationStatus.MISSING_TRUSTED_HASH, "", "")
		
	# Key = project-relative "res://..." path when inside the project (portable), else the absolute path.
	var file_key = to_db_key(file_path)

	var expected_hash = _get_trusted_hash_from_json(file_key)
	
	if expected_hash.is_empty():
		return VerificationResult.new(VerificationStatus.MISSING_TRUSTED_HASH, computed_hash, "")
		
	if computed_hash == expected_hash:
		return VerificationResult.new(VerificationStatus.VALID, computed_hash, expected_hash)
	else:
		return VerificationResult.new(VerificationStatus.TAMPERED, computed_hash, expected_hash)

## ---------------------------------------------------------------------------
## Portable keys
## Files inside the Godot project are stored as "res://<relative path>" so the DB
## works on any machine. Files outside the project keep their absolute path
## (those cannot be portable).
## ---------------------------------------------------------------------------

static func _project_root() -> String:
	var root := ProjectSettings.globalize_path("res://").replace("\\", "/")
	if not root.ends_with("/"):
		root += "/"
	return root

## Converts any path (absolute, backslashes, res://) into the key stored in the DB.
static func to_db_key(path: String) -> String:
	var p := path.strip_edges().replace("\\", "/")
	if p.begins_with("res://"):
		return p
	var root := _project_root()
	var inside := p.to_lower().begins_with(root.to_lower()) if OS.get_name() == "Windows" else p.begins_with(root)
	if inside:
		return "res://" + p.substr(root.length())
	return p

## Old DBs hold absolute paths, possibly from another computer. Map them into the
## project when possible: either they already point inside this project, or they
## contain "/<project folder name>/" (e.g. ".../Group6Comp7082/fortify/tests/a.txt")
## and the remapped file exists here. Otherwise the key is left untouched.
static func _migrate_key(key: String) -> String:
	var k := to_db_key(key)
	if k.begins_with("res://"):
		return k
	var folder := _project_root().trim_suffix("/").get_file()
	if folder.is_empty():
		return k
	var marker := "/" + folder + "/"
	var idx := k.find(marker)
	if idx >= 0:
		var candidate := "res://" + k.substr(idx + marker.length())
		if FileAccess.file_exists(candidate):
			return candidate
	return k

## Returns a copy of db with every key converted by _migrate_key.
static func _normalize_keys(db: Dictionary) -> Dictionary:
	var out := {}
	for key in db.keys():
		var new_key := _migrate_key(str(key))
		# On collision keep the record that was most recently updated.
		if out.has(new_key):
			var old_rec = out[new_key]
			var new_rec = db[key]
			var old_t := str(old_rec.get("last_updated", "")) if old_rec is Dictionary else ""
			var new_t := str(new_rec.get("last_updated", "")) if new_rec is Dictionary else ""
			if new_t < old_t:
				continue
		out[new_key] = db[key]
	return out

## Loads the databases merged into one dictionary ({} if none exist). Debug/editor:
## project DB + local DB. Release: local DB only. Keys are normalised in memory; call
## migrate_database() to persist the normalised keys.
static func load_database() -> Dictionary:
	return _normalize_keys(_load_raw_database())

static func database_exists() -> bool:
	return FileAccess.file_exists(LOCAL_DB_PATH) or (project_db_enabled() and FileAccess.file_exists(JSON_DB_PATH))

static func _read_json_file(path: String) -> Dictionary:
	if not FileAccess.file_exists(path):
		return {}
	var file = FileAccess.open(path, FileAccess.READ)
	if file == null:
		return {}
	var parsed = JSON.parse_string(file.get_as_text())
	return parsed if parsed is Dictionary else {}

## silent = true: a failed write is not reported (used for the optional project DB).
static func _write_json_file(path: String, db: Dictionary, silent: bool = false) -> bool:
	var file = FileAccess.open(path, FileAccess.WRITE)
	if file == null:
		if not silent:
			push_error("Cannot write %s (error %d)" % [path, FileAccess.get_open_error()])
		return false
	file.store_string(JSON.stringify(db, "	"))
	file.close()
	return true

## Project DB (debug only) + local DB merged.
static func _load_raw_database() -> Dictionary:
	var merged := _read_json_file(JSON_DB_PATH) if project_db_enabled() else {}
	merged.merge(_read_json_file(LOCAL_DB_PATH), true)
	return merged

## Splits a merged DB by key: "res://" keys -> project DB, everything else -> local DB.
static func _split_database(db: Dictionary) -> Array[Dictionary]:
	var project_part := {}
	var local_part := {}
	for key in db.keys():
		if str(key).begins_with("res://"):
			project_part[key] = db[key]
		else:
			local_part[key] = db[key]
	return [project_part, local_part]

## Writes a merged DB back.
## Debug/editor: "res://" records -> project DB (silently skipped when empty or not
## writable), everything else -> local DB.
## Release: everything -> local DB; the project DB is never touched.
## The local file is only created when it has records (or already exists).
static func save_database(db: Dictionary) -> bool:
	var project_part := {}
	var local_part := db
	if project_db_enabled():
		var parts := _split_database(db)
		project_part = parts[0]
		local_part = parts[1]
		if not project_part.is_empty() or FileAccess.file_exists(JSON_DB_PATH):
			_write_json_file(JSON_DB_PATH, project_part, true)   # optional: never an error
	if not local_part.is_empty() or FileAccess.file_exists(LOCAL_DB_PATH):
		return _write_json_file(LOCAL_DB_PATH, local_part)
	return true

## Normalises keys and moves records into the right file (e.g. old absolute keys
## that were stored in the project DB). Returns true if anything was rewritten.
static func migrate_database() -> bool:
	var project_raw := _read_json_file(JSON_DB_PATH) if project_db_enabled() else {}
	var local_raw := _read_json_file(LOCAL_DB_PATH)
	var merged := project_raw.duplicate()
	merged.merge(local_raw, true)
	var normalized := _normalize_keys(merged)
	var new_project := {}
	var new_local := normalized
	if project_db_enabled():
		var parts := _split_database(normalized)
		new_project = parts[0]
		new_local = parts[1]
	if new_project.keys() == project_raw.keys() and new_local.keys() == local_raw.keys():
		return false
	return save_database(normalized)

## ---------------------------------------------------------------------------
## Registering files / folders
## ---------------------------------------------------------------------------

## Recursively lists every file under dir_path (sorted). Skips hidden entries
## (names starting with ".", e.g. .git, .godot) and the trusted-hash DB itself.
static func collect_files(dir_path: String) -> Array[String]:
	var result: Array[String] = []
	_collect_files_into(dir_path.replace("\\", "/").trim_suffix("/"), result)
	result.sort()
	return result

static func _collect_files_into(dir_path: String, result: Array[String]) -> void:
	var dir := DirAccess.open(dir_path)
	if dir == null:
		push_warning("Cannot open folder: " + dir_path)
		return
	dir.list_dir_begin()
	var name := dir.get_next()
	while name != "":
		if not name.begins_with("."):
			var full := dir_path + "/" + name
			if dir.current_is_dir():
				_collect_files_into(full, result)
			elif to_db_key(full) != JSON_DB_PATH and full != ProjectSettings.globalize_path(LOCAL_DB_PATH):
				result.append(full)
		name = dir.get_next()
	dir.list_dir_end()

## Hashes every path and stores all records with ONE database write.
## Returns { "registered": [{path, key, hash}], "failed": [path] }
static func register_files(paths: Array, algorithm_name: String) -> Dictionary:
	var out := {"registered": [], "failed": []}
	var db := load_database()
	var now := Time.get_datetime_string_from_system()
	for p in paths:
		var path := str(p)
		var h := HashGenerator.generate_hash(path, algorithm_name)
		if h.is_empty():
			out.failed.append(path)
			continue
		var key := to_db_key(path)
		db[key] = {"algorithm": algorithm_name, "expected_hash": h, "last_updated": now}
		out.registered.append({"path": path, "key": key, "hash": h})
	if not out.registered.is_empty():
		save_database(db)
	return out

## Registers every file under a folder (recursive).
static func register_folder(dir_path: String, algorithm_name: String) -> Dictionary:
	return register_files(collect_files(dir_path), algorithm_name)

## Verifies one DB record using the algorithm stored in that record.
static func verify_record(file_path: String, record: Dictionary) -> VerificationResult:
	var algo: String = str(record.get("algorithm", "sha256"))
	var expected: String = str(record.get("expected_hash", ""))
	var computed := HashGenerator.generate_hash(file_path, algo)
	if computed.is_empty() or expected.is_empty():
		return VerificationResult.new(VerificationStatus.MISSING_TRUSTED_HASH, computed, expected)
	if computed == expected:
		return VerificationResult.new(VerificationStatus.VALID, computed, expected)
	return VerificationResult.new(VerificationStatus.TAMPERED, computed, expected)

## Verifies every record in the DB and writes the integrity log.
## trigger: "scheduled" or "manual". log_path: "" -> default daily log.
## Returns { "entries": [{path, algorithm, result}], "valid", "tampered", "missing", "exit_code" }
## exit_code: 0 = all valid (or nothing registered yet), 1 = tampered/missing found.
static func run_full_check(trigger: String = "manual", log_path: String = "") -> Dictionary:
	if log_path.is_empty():
		log_path = IntegrityLogger.default_log_path()

	var summary := {"entries": [], "valid": 0, "tampered": 0, "missing": 0, "exit_code": 0}
	if migrate_database():
		IntegrityLogger.write_line(log_path, "MIGRATE", "database keys normalised / records moved to the right database")
	var db := load_database()

	# No database / no records simply means nothing has been registered yet: not an error.
	IntegrityLogger.write_line(log_path, "RUN START", "trigger=%s | algorithm=per-record | records=%d" % [trigger, db.size()])

	for path in db.keys():
		var record = db[path]
		if not (record is Dictionary):
			record = {}
		var result := verify_record(path, record)
		summary.entries.append({"path": path, "algorithm": record.get("algorithm", ""), "result": result})

		match result.status:
			VerificationStatus.VALID:
				summary.valid += 1
				IntegrityLogger.write_line(log_path, "VALID", path)
			VerificationStatus.TAMPERED:
				summary.tampered += 1
				IntegrityLogger.write_line(log_path, "TAMPERED", "%s | expected=%s | actual=%s" % [path, result.expected_hash, result.computed_hash])
			_:
				summary.missing += 1
				IntegrityLogger.write_line(log_path, "MISSING", path)

	if summary.tampered > 0 or summary.missing > 0:
		summary.exit_code = 1
	IntegrityLogger.write_line(log_path, "RUN END", "valid=%d tampered=%d missing=%d | exit=%d" % [summary.valid, summary.tampered, summary.missing, summary.exit_code])
	return summary

static func _get_trusted_hash_from_json(file_key: String) -> String:
	var parsed := load_database()
	if parsed.has(file_key):
		var entry = parsed[file_key]
		if entry is Dictionary and entry.has("expected_hash"):
			return entry["expected_hash"]
	return ""
