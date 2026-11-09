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

const JSON_DB_PATH = "res://tools/fileIntegrityCheck/trusted_hashes.json"

static func verify_file(file_path: String, algorithm_name: String = "sha256") -> VerificationResult:
	var computed_hash = HashGenerator.generate_hash(file_path, algorithm_name)
	if computed_hash.is_empty():
		return VerificationResult.new(VerificationStatus.MISSING_TRUSTED_HASH, "", "")
		
	# FIXED: Use full path as the key so files with same name don't clash
	var file_key = file_path 
	
	var expected_hash = _get_trusted_hash_from_json(file_key)
	
	if expected_hash.is_empty():
		return VerificationResult.new(VerificationStatus.MISSING_TRUSTED_HASH, computed_hash, "")
		
	if computed_hash == expected_hash:
		return VerificationResult.new(VerificationStatus.VALID, computed_hash, expected_hash)
	else:
		return VerificationResult.new(VerificationStatus.TAMPERED, computed_hash, expected_hash)

## Loads the whole trusted-hash database ({} if missing/invalid).
static func load_database() -> Dictionary:
	if not FileAccess.file_exists(JSON_DB_PATH):
		return {}
	var file = FileAccess.open(JSON_DB_PATH, FileAccess.READ)
	if file == null:
		return {}
	var parsed = JSON.parse_string(file.get_as_text())
	return parsed if parsed is Dictionary else {}

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
## exit_code: 0 = all valid, 1 = tampered/missing found, 2 = error (no database).
static func run_full_check(trigger: String = "manual", log_path: String = "") -> Dictionary:
	if log_path.is_empty():
		log_path = IntegrityLogger.default_log_path()

	var summary := {"entries": [], "valid": 0, "tampered": 0, "missing": 0, "exit_code": 0}
	var db := load_database()

	if db.is_empty() and not FileAccess.file_exists(JSON_DB_PATH):
		IntegrityLogger.write_line(log_path, "ERROR", "trusted hash database not found: " + JSON_DB_PATH)
		summary.exit_code = 2
		return summary

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
	if not FileAccess.file_exists(JSON_DB_PATH):
		return ""
		
	var file = FileAccess.open(JSON_DB_PATH, FileAccess.READ)
	var json_text = file.get_as_text()
	var parsed = JSON.parse_string(json_text)
	
	if parsed is Dictionary and parsed.has(file_key):
		var entry = parsed[file_key]
		if entry is Dictionary and entry.has("expected_hash"):
			return entry["expected_hash"]
			
	return ""
