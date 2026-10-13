class_name virusDB
extends RefCounted
## Simple SHA-256 signature database.
##
## In memory: Dictionary keyed by lowercase hex SHA-256 -> {name, source, added}
## On disk:   binary file (raw 32-byte hashes) with a trailing SHA-256 checksum
##            to detect corruption. NOTE: the checksum is NOT tamper protection.
##            For that you'd need a cryptographic signature (see bottom note).
##
## File layout:
##   "VHDB" | u32 version | u32 count
##   count x [ 32 bytes hash | string name | string source | u64 added ]
##   32 bytes SHA-256 of everything above

const DB_PATH := "user://signatures.db"
const MAGIC := "VHDB"
const VERSION := 1
const HASH_BYTES := 32

var _signatures: Dictionary = {}  # hex String -> Dictionary


# ---------------------------------------------------------------------------
# Adding signatures
# ---------------------------------------------------------------------------

## Add a hash directly (hex string). Returns OK, ERR_INVALID_PARAMETER if the
## hash is malformed, or ERR_ALREADY_EXISTS if it's already in the DB.
func add_hash(hex: String, sig_name: String, source: String = "manual") -> Error:
	var normalized := normalize_hash(hex)
	if normalized.is_empty():
		return ERR_INVALID_PARAMETER
	if _signatures.has(normalized):
		return ERR_ALREADY_EXISTS
	_signatures[normalized] = {
		"name": sig_name,
		"source": source,
		"added": int(Time.get_unix_time_from_system()),
	}
	return OK


## TESTING HELPER: hash a file on disk and add it as a "virus" signature.
## Accepts res://, user://, or absolute paths.
## Returns OK, ERR_FILE_CANT_OPEN, or ERR_ALREADY_EXISTS.
func add_file(path: String, sig_name: String = "") -> Error:
	var hex := hash_file(path)
	if hex.is_empty():
		return ERR_FILE_CANT_OPEN
	if sig_name.is_empty():
		sig_name = "Test.%s" % path.get_file()
	return add_hash(hex, sig_name, "file:" + path.get_file())


func remove_hash(hex: String) -> bool:
	return _signatures.erase(normalize_hash(hex))


# ---------------------------------------------------------------------------
# Lookup / scanning
# ---------------------------------------------------------------------------

## Returns the signature entry for a hash, or an empty Dictionary if unknown.
func lookup(hex: String) -> Dictionary:
	return _signatures.get(normalize_hash(hex), {})


func has_hash(hex: String) -> bool:
	return _signatures.has(normalize_hash(hex))


## Hash a file and check it against the DB.
## Returns {"error": Error, "hash": String, "infected": bool, "name": String}
func scan_file(path: String) -> Dictionary:
	var result := {"error": OK, "hash": "", "infected": false, "name": ""}
	var hex := hash_file(path)
	if hex.is_empty():
		result["error"] = ERR_FILE_CANT_OPEN
		return result
	result["hash"] = hex
	var entry: Dictionary = _signatures.get(hex, {})
	if not entry.is_empty():
		result["infected"] = true
		result["name"] = entry["name"]
	return result


func size() -> int:
	return _signatures.size()


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

## SHA-256 of a file as lowercase hex, or "" on failure.
## FileAccess.get_sha256 reads in chunks, so large files are fine.
static func hash_file(path: String) -> String:
	if not FileAccess.file_exists(path):
		return ""
	return FileAccess.get_sha256(path)


## Returns lowercase 64-char hex, or "" if the input isn't a valid SHA-256.
static func normalize_hash(hex: String) -> String:
	var h := hex.strip_edges().to_lower()
	if h.length() != HASH_BYTES * 2 or not h.is_valid_hex_number(false):
		return ""
	return h


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

func save_db(path: String = DB_PATH) -> Error:
	var buf := StreamPeerBuffer.new()
	buf.put_data(MAGIC.to_ascii_buffer())
	buf.put_u32(VERSION)
	buf.put_u32(_signatures.size())
	for hex: String in _signatures:
		var entry: Dictionary = _signatures[hex]
		buf.put_data(hex.hex_decode())  # 32 raw bytes
		buf.put_string(entry["name"])
		buf.put_string(entry["source"])
		buf.put_u64(entry["added"])

	var body: PackedByteArray = buf.data_array
	var checksum := _sha256_bytes(body)

	# Write to a temp file first, then rename, so a crash mid-write can't
	# corrupt the existing database.
	var tmp_path := path + ".tmp"
	var file := FileAccess.open(tmp_path, FileAccess.WRITE)
	if file == null:
		return FileAccess.get_open_error()
	file.store_buffer(body)
	file.store_buffer(checksum)
	file.close()

	return DirAccess.rename_absolute(
		ProjectSettings.globalize_path(tmp_path),
		ProjectSettings.globalize_path(path)
	)


func load_db(path: String = DB_PATH) -> Error:
	if not FileAccess.file_exists(path):
		return ERR_FILE_NOT_FOUND

	var bytes := FileAccess.get_file_as_bytes(path)
	# header (4+4+4) + checksum (32)
	if bytes.size() < 12 + HASH_BYTES:
		return ERR_FILE_CORRUPT

	var body := bytes.slice(0, bytes.size() - HASH_BYTES)
	var stored_checksum := bytes.slice(bytes.size() - HASH_BYTES)
	if _sha256_bytes(body) != stored_checksum:
		return ERR_FILE_CORRUPT

	var buf := StreamPeerBuffer.new()
	buf.data_array = body

	if body.slice(0, 4).get_string_from_ascii() != MAGIC:
		return ERR_FILE_UNRECOGNIZED
	buf.seek(4)
	if buf.get_u32() != VERSION:
		return ERR_FILE_UNRECOGNIZED
	var count := buf.get_u32()

	var loaded := {}
	for i in count:
		# Guard against truncated/malformed data
		if buf.get_available_bytes() < HASH_BYTES:
			return ERR_FILE_CORRUPT
		var raw: PackedByteArray = buf.get_data(HASH_BYTES)[1]
		var sig_name := buf.get_string()
		var source := buf.get_string()
		var added := buf.get_u64()
		loaded[raw.hex_encode()] = {"name": sig_name, "source": source, "added": added}

	_signatures = loaded
	return OK


static func _sha256_bytes(data: PackedByteArray) -> PackedByteArray:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(data)
	return ctx.finish()


# ---------------------------------------------------------------------------
# NOTE ON TAMPER PROTECTION
# The trailing checksum only catches accidental corruption: anyone who can
# edit the file can recompute it. Once you add real updates, ship a detached
# signature (e.g. Ed25519/RSA via Godot's Crypto class: Crypto.sign /
# Crypto.verify with a public key embedded in your app) and verify it before
# loading a downloaded database.
# ---------------------------------------------------------------------------
