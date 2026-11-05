class_name FileIntegrityManager
extends RefCounted

const HashGenerator = preload("res://tools/fileIntegrityCheck/hash_generator.gd")

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
