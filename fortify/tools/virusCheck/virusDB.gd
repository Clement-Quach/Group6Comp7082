class_name virusDB
extends RefCounted
## Compact SHA-256 signature database, built to hold millions of hashes,
## plus the code that pulls new hashes from MalwareBazaar.
##
## In memory (struct-of-arrays, ~57 bytes per signature instead of the several
## hundred a Dictionary-of-Dictionaries needs):
##   _hashes   PackedByteArray   32 raw bytes per entry
##   _names    PackedInt32Array  index into the shared string table
##   _sources  PackedInt32Array  index into the shared string table
##   _added    PackedInt64Array  unix time
##   _slots    PackedInt32Array  open-addressing hash table -> entry index
##   _strings  PackedStringArray every distinct name/source stored ONCE
## Malware family names repeat thousands of times, so the string table is tiny.
## Lookups are O(1): SHA-256 is already uniformly random, so its first 4 bytes
## are used directly as the hash-table position.
##
## On disk (little-endian, raw arrays so load/save are bulk I/O with no
## per-entry parsing):
##   "VHDB" | u32 version | u32 count | u32 capacity | u32 strtab_len
##   string table (u32 n, then n x length-prefixed string)
##   count x 32 B hashes | count x i32 names | count x i32 sources | count x i64 added
##   capacity x i32 slot table
##   32 bytes SHA-256 of everything above
##
## NOTE: the checksum only detects accidental corruption, it is NOT tamper
## protection. See the note at the bottom.

const DB_PATH := "res://tools/virusCheck/dbFolder/virus_hashed.db"

const MAGIC := "VHDB"
const VERSION := 2
const HASH_BYTES := 32
const HEADER_BYTES := 20
const INITIAL_CAPACITY := 1024

const SLOT_EMPTY := -1
const SLOT_TOMB := -2    # removed entry, keeps probe chains intact
const NAME_DEAD := -1    # marks a removed entry in _names

var _hashes := PackedByteArray()
var _names := PackedInt32Array()
var _sources := PackedInt32Array()
var _added := PackedInt64Array()
var _slots := PackedInt32Array()
var _strings := PackedStringArray()
var _string_ids: Dictionary = {}   # String -> index in _strings

var _capacity := INITIAL_CAPACITY  # slot count, always a power of two
var _mask := INITIAL_CAPACITY - 1
var _count := 0                    # live signatures
var _used := 0                     # non-empty slots (live + tombstones)
var _dead := 0                     # removed entries still sitting in the arrays


func _init() -> void:
	_rebuild_slots(INITIAL_CAPACITY)


# ---------------------------------------------------------------------------
# Signatures: add / remove / lookup
# ---------------------------------------------------------------------------

## Add a hash directly (hex string). Returns OK, ERR_INVALID_PARAMETER if the
## hash is malformed, or ERR_ALREADY_EXISTS if it's already in the DB.
## added_unix < 0 means "now".
func add_hash(hex: String, sig_name: String, source: String = "manual", added_unix: int = -1) -> Error:
	var normalized := normalize_hash(hex)
	if normalized.is_empty():
		return ERR_INVALID_PARAMETER
	if added_unix < 0:
		added_unix = int(Time.get_unix_time_from_system())
	if not _add_raw(normalized.hex_decode(), sig_name, source, added_unix):
		return ERR_ALREADY_EXISTS
	return OK


## Hash a file on disk and add it as a "virus" signature.
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
	var slot := _slot_of(hex)
	if slot == -1:
		return false
	var e := _slots[slot]
	_slots[slot] = SLOT_TOMB
	_names[e] = NAME_DEAD
	_count -= 1
	_dead += 1
	# Reclaim memory once a good chunk of the arrays is garbage
	if _dead >= 10000 and _dead * 4 > _names.size():
		_rebuild_slots(_capacity_for(_count))
	return true


## Returns the signature entry for a hash, or an empty Dictionary if unknown.
func lookup(hex: String) -> Dictionary:
	var slot := _slot_of(hex)
	if slot == -1:
		return {}
	var e := _slots[slot]
	return {
		"name": _string_at(_names[e]),
		"source": _string_at(_sources[e]),
		"added": _added[e],
	}


func has_hash(hex: String) -> bool:
	return _slot_of(hex) != -1


## Hash a file and check it against the DB.
## Returns {"error": Error, "hash": String, "infected": bool, "name": String}
func scan_file(path: String) -> Dictionary:
	var result := {"error": OK, "hash": "", "infected": false, "name": ""}
	var hex := hash_file(path)
	if hex.is_empty():
		result["error"] = ERR_FILE_CANT_OPEN
		return result
	result["hash"] = hex
	var entry := lookup(hex)
	if not entry.is_empty():
		result["infected"] = true
		result["name"] = entry["name"]
	return result


func size() -> int:
	return _count


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
	# Make sure the arrays and slot table contain no removed entries/tombstones
	if _dead > 0:
		_rebuild_slots(_capacity_for(_count))

	var strtab_buf := StreamPeerBuffer.new()
	strtab_buf.put_u32(_strings.size())
	for s in _strings:
		strtab_buf.put_string(s)
	var strtab := strtab_buf.data_array

	var header := MAGIC.to_ascii_buffer()
	header.resize(HEADER_BYTES)
	header.encode_u32(4, VERSION)
	header.encode_u32(8, _names.size())
	header.encode_u32(12, _capacity)
	header.encode_u32(16, strtab.size())

	DirAccess.make_dir_recursive_absolute(ProjectSettings.globalize_path(path.get_base_dir()))

	# Write to a temp file first, then rename, so a crash mid-write can't
	# corrupt the existing database. The checksum is computed while streaming,
	# so the whole database is never duplicated in memory.
	var tmp_path := path + ".tmp"
	var file := FileAccess.open(tmp_path, FileAccess.WRITE)
	if file == null:
		return FileAccess.get_open_error()

	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	_write_chunk(file, ctx, header)
	_write_chunk(file, ctx, strtab)
	_write_chunk(file, ctx, _hashes)
	_write_chunk(file, ctx, _names.to_byte_array())
	_write_chunk(file, ctx, _sources.to_byte_array())
	_write_chunk(file, ctx, _added.to_byte_array())
	_write_chunk(file, ctx, _slots.to_byte_array())
	file.store_buffer(ctx.finish())

	var write_err := file.get_error()
	file.close()
	if write_err != OK:
		return write_err

	return DirAccess.rename_absolute(
		ProjectSettings.globalize_path(tmp_path),
		ProjectSettings.globalize_path(path)
	)


## Replaces the in-memory database with the one on disk. On any error the
## current in-memory contents are left untouched.
func load_db(path: String = DB_PATH) -> Error:
	if not FileAccess.file_exists(path):
		return ERR_FILE_NOT_FOUND

	var f := FileAccess.open(path, FileAccess.READ)
	if f == null:
		return FileAccess.get_open_error()
	var total := f.get_length()
	if total < HEADER_BYTES + HASH_BYTES:
		return ERR_FILE_CORRUPT

	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)

	var header := _read_chunk(f, ctx, HEADER_BYTES)
	if header.slice(0, 4).get_string_from_ascii() != MAGIC or header.decode_u32(4) != VERSION:
		return ERR_FILE_UNRECOGNIZED
	var count := header.decode_u32(8)
	var capacity := header.decode_u32(12)
	var strtab_len := header.decode_u32(16)

	# Validate sizes BEFORE allocating anything based on them
	if capacity < 2 or (capacity & (capacity - 1)) != 0 or capacity <= count:
		return ERR_FILE_CORRUPT
	var expected := HEADER_BYTES + strtab_len + count * (HASH_BYTES + 4 + 4 + 8) + capacity * 4 + HASH_BYTES
	if expected != total:
		return ERR_FILE_CORRUPT

	var strtab := _read_chunk(f, ctx, strtab_len)
	var hashes := _read_chunk(f, ctx, count * HASH_BYTES)
	var names_b := _read_chunk(f, ctx, count * 4)
	var sources_b := _read_chunk(f, ctx, count * 4)
	var added_b := _read_chunk(f, ctx, count * 8)
	var slots_b := _read_chunk(f, ctx, capacity * 4)
	var stored_checksum := f.get_buffer(HASH_BYTES)
	f.close()

	if ctx.finish() != stored_checksum:
		return ERR_FILE_CORRUPT

	var sb := StreamPeerBuffer.new()
	sb.data_array = strtab
	var str_count := sb.get_u32()
	if str_count > strtab_len:
		return ERR_FILE_CORRUPT
	var strings := PackedStringArray()
	var ids := {}
	for i in str_count:
		var s := sb.get_string()
		strings.append(s)
		ids[s] = i

	_hashes = hashes
	_names = names_b.to_int32_array()
	_sources = sources_b.to_int32_array()
	_added = added_b.to_int64_array()
	_slots = slots_b.to_int32_array()
	_strings = strings
	_string_ids = ids
	_capacity = capacity
	_mask = capacity - 1
	_count = count
	_used = count   # saved DBs never contain tombstones
	_dead = 0
	return OK


## HashingContext.update() can reject empty input, so empty chunks are skipped.
func _write_chunk(file: FileAccess, ctx: HashingContext, chunk: PackedByteArray) -> void:
	if chunk.is_empty():
		return
	ctx.update(chunk)
	file.store_buffer(chunk)


func _read_chunk(file: FileAccess, ctx: HashingContext, length: int) -> PackedByteArray:
	if length <= 0:
		return PackedByteArray()
	var chunk := file.get_buffer(length)
	if not chunk.is_empty():
		ctx.update(chunk)
	return chunk


# ---------------------------------------------------------------------------
# MalwareBazaar bulk exports
# ---------------------------------------------------------------------------
# NOTHING here runs automatically. Call pull_from_malwarebazaar() yourself and
# `await` it. It needs a Node inside the scene tree (the "host") because it
# creates an HTTPRequest and waits for frames, which a RefCounted can't do:
#
#     # last 48 hours of hashes (small, fast). This is the normal one to use.
#     var r: Dictionary = await db.pull_from_malwarebazaar(self)
#
#     # every hash ever, optionally filtered by file type
#     var r: Dictionary = await db.pull_from_malwarebazaar(self, true, PackedStringArray(["exe", "dll"]))
#
#     if r["error"] == OK: print(r["message"])
#
# It saves the DB itself after a successful pull and records the time. It
# only returns results and never logs, so the caller decides what to show.
#
# abuse.ch asks that "recent" is fetched at most every 5 minutes and "full" at
# most once per hour, so a pull inside those windows is refused with
# ERR_UNAVAILABLE. get_seconds_until_next_pull() tells you how long to wait.
#
# The auth key is read from SECRETS_PATH:
#     [malware_bazaar]
#     malware_bazaar_auth_key="key"

const SECRETS_PATH := "res://secrets.cfg"
const PULL_STATE_PATH := "user://malwarebazaar_state.cfg"
const MB_EXPORT_URL := "https://mb-api.abuse.ch/v2/files/exports/%s/%s"  # key, file name
const MB_SOURCE := "malwarebazaar"
const MB_RECENT_FILE := "recent.csv"
const MB_FULL_FILE := "full.csv.zip"
const MB_RECENT_MIN_INTERVAL := 300     # seconds, abuse.ch: generated every 5 min
const MB_FULL_MIN_INTERVAL := 3600      # seconds, abuse.ch: generated hourly
const MB_RECENT_WINDOW := 48 * 3600     # recent.csv only covers the last 48 h
const MB_RECENT_TIMEOUT := 60.0
const MB_FULL_TIMEOUT := 900.0
const MB_TMP_DOWNLOAD := "user://mb_download.tmp"
const MB_TMP_CSV := "user://mb_export.csv"
const MB_YIELD_EVERY := 20000           # rows between frames so the UI doesn't freeze

var _pulling := false


## Unix time of the last SUCCESSFUL pull, or 0 if never.
## which: "recent", "full", or "any" (whichever is newer)
func get_last_pull_time(which: String = "any") -> int:
	var cfg := ConfigFile.new()
	if cfg.load(PULL_STATE_PATH) != OK:
		return 0
	var recent := int(cfg.get_value("malware_bazaar", "last_pull_recent_unix", 0))
	var full := int(cfg.get_value("malware_bazaar", "last_pull_full_unix", 0))
	match which:
		"recent": return recent
		"full": return full
		_: return maxi(recent, full)


func get_last_pull_string(which: String = "any") -> String:
	var t := get_last_pull_time(which)
	if t == 0:
		return "never"
	return Time.get_datetime_string_from_unix_time(t, true) + " UTC"


## 0 means you can pull now.
func get_seconds_until_next_pull(full: bool = false) -> int:
	var last := get_last_pull_time("full" if full else "recent")
	var interval := MB_FULL_MIN_INTERVAL if full else MB_RECENT_MIN_INTERVAL
	var now := int(Time.get_unix_time_from_system())
	return maxi(0, last + interval - now)


## full = false -> recent.csv (last 48 h).  full = true -> full.csv.zip (everything).
## file_types: optional filter on MalwareBazaar's file type, e.g. ["exe", "dll"].
## Empty = keep everything.
## host: any Node inside the scene tree.
##
## Returns {error, message, received, added, skipped, filtered, invalid}.
## On failure error != OK and message says why.
func pull_from_malwarebazaar(host: Node, full: bool = false, file_types: PackedStringArray = PackedStringArray()) -> Dictionary:
	var result := {
		"error": OK,
		"message": "",
		"received": 0,   # rows read from the export
		"added": 0,      # new hashes put into the DB
		"skipped": 0,    # already in the DB
		"filtered": 0,   # dropped by file_types
		"invalid": 0,    # malformed hash
	}

	if host == null or not host.is_inside_tree():
		return _mb_fail(result, ERR_UNCONFIGURED, "pull_from_malwarebazaar needs a host node that is inside the scene tree")
	if _pulling:
		return _mb_fail(result, ERR_BUSY, "a MalwareBazaar pull is already running")

	var key := _mb_load_auth_key()
	if key.is_empty():
		return _mb_fail(result, ERR_UNCONFIGURED, "no malware_bazaar_auth_key found in " + SECRETS_PATH)

	var wait := get_seconds_until_next_pull(full)
	if wait > 0:
		return _mb_fail(result, ERR_UNAVAILABLE,
			"too soon to pull the %s export again, try in %d s" % ["full" if full else "recent", wait])

	var url := MB_EXPORT_URL % [key, MB_FULL_FILE if full else MB_RECENT_FILE]
	var last_recent := get_last_pull_time("recent")

	_pulling = true
	var err := await _mb_pull_impl(host, url, full, file_types, result)
	_pulling = false
	_mb_cleanup_tmp()

	if err != OK:
		return _mb_fail(result, err, result["message"] if not str(result["message"]).is_empty() else error_string(err))

	# Persist the DB BEFORE recording the pull, so a failed save isn't counted
	if result["added"] > 0:
		var save_err := save_db()
		if save_err != OK:
			return _mb_fail(result, save_err, "pulled hashes but save_db failed: %s" % error_string(save_err))

	var now := int(Time.get_unix_time_from_system())
	_mb_set_last_pull_time(full, now)

	var msg := "MalwareBazaar %s: %d rows, %d added, %d already known, %d filtered out, %d invalid (DB now %d)" % [
		"full" if full else "recent",
		result["received"], result["added"], result["skipped"],
		result["filtered"], result["invalid"], _count
	]
	# recent.csv only covers 48 h, so a longer gap means samples were missed
	if not full and last_recent > 0 and now - last_recent > MB_RECENT_WINDOW:
		msg += ". Your last recent pull was over 48 h ago, so samples in between may be missing (a full pull would cover them)"
	result["message"] = msg
	return result


## Download -> (unzip) -> import. Returns an Error and puts any message in result["message"].
func _mb_pull_impl(host: Node, url: String, full: bool, file_types: PackedStringArray, result: Dictionary) -> Error:
	var dl := await _mb_download(host, url, MB_FULL_TIMEOUT if full else MB_RECENT_TIMEOUT)
	if dl["error"] != OK:
		result["message"] = dl["message"]
		return dl["error"]

	var csv_path := MB_TMP_DOWNLOAD
	if full:
		var ex := _mb_extract_zip(MB_TMP_DOWNLOAD, MB_TMP_CSV)
		if ex != OK:
			result["message"] = "could not unzip the full export: %s" % error_string(ex)
			return ex
		csv_path = MB_TMP_CSV

	var imp := await _mb_import_csv(host, csv_path, file_types, result)
	if imp != OK:
		result["message"] = "could not read the export: %s" % error_string(imp)
	return imp


## Streams the export straight to disk (it can be hundreds of MB).
## The auth key is part of the URL, so the URL is never put in a message.
func _mb_download(host: Node, url: String, timeout: float) -> Dictionary:
	var http := HTTPRequest.new()
	http.download_file = MB_TMP_DOWNLOAD
	http.timeout = timeout
	host.add_child(http)

	var err := http.request(url)
	if err != OK:
		http.queue_free()
		return {"error": err, "message": "could not start download: %s" % error_string(err)}

	var resp: Array = await http.request_completed   # [result, code, headers, body]
	http.queue_free()

	var net_result: int = resp[0]
	var code: int = resp[1]

	if net_result == HTTPRequest.RESULT_TIMEOUT:
		return {"error": ERR_TIMEOUT, "message": "MalwareBazaar download timed out"}
	if net_result != HTTPRequest.RESULT_SUCCESS:
		return {"error": ERR_CANT_CONNECT, "message": "network error (HTTPRequest result %d)" % net_result}
	if code == 401 or code == 403:
		return {"error": ERR_UNAUTHORIZED, "message": "MalwareBazaar rejected the auth key (HTTP %d)" % code}
	if code != 200:
		return {"error": ERR_CANT_CONNECT, "message": "MalwareBazaar returned HTTP %d" % code}
	return {"error": OK, "message": ""}


## ZIPReader can't stream, so the CSV is briefly held in RAM (~500 MB for full)
## and written out so it can then be read line by line.
func _mb_extract_zip(zip_path: String, out_path: String) -> Error:
	var zr := ZIPReader.new()
	var err := zr.open(zip_path)
	if err != OK:
		return err

	var csv_name := ""
	for entry in zr.get_files():
		if entry.to_lower().ends_with(".csv"):
			csv_name = entry
			break
	if csv_name.is_empty():
		zr.close()
		return ERR_FILE_UNRECOGNIZED

	var data := zr.read_file(csv_name)
	zr.close()

	var out := FileAccess.open(out_path, FileAccess.WRITE)
	if out == null:
		return FileAccess.get_open_error()
	out.store_buffer(data)
	out.close()
	return OK


## Reads the CSV line by line. Columns are found by NAME from the header row
## (sha256_hash, signature, file_type_guess), so column order doesn't matter and
## the "# ..." comment lines abuse.ch puts above the header are skipped.
func _mb_import_csv(host: Node, path: String, file_types: PackedStringArray, result: Dictionary) -> Error:
	var f := FileAccess.open(path, FileAccess.READ)
	if f == null:
		return FileAccess.get_open_error()

	var wanted := {}
	for t in file_types:
		wanted[t.strip_edges().to_lower().trim_prefix(".")] = true

	var i_sha := -1
	var i_sig := -1
	var i_type := -1
	var rows := 0

	while not f.eof_reached():
		var row := f.get_csv_line()

		# Still looking for the header row
		if i_sha == -1:
			var cols: Array[String] = []
			for c in row:
				cols.append(c.strip_edges().trim_prefix("#").strip_edges().to_lower())
			i_sha = cols.find("sha256_hash")
			if i_sha != -1:
				i_sig = cols.find("signature")
				i_type = cols.find("file_type_guess")
				if i_type == -1:
					i_type = cols.find("file_type")
			continue

		if row.size() <= i_sha or row[i_sha].strip_edges().is_empty():
			continue  # blank line or trailing comment
		if row[0].begins_with("#"):
			continue

		result["received"] += 1
		rows += 1
		if rows % MB_YIELD_EVERY == 0:
			await host.get_tree().process_frame

		var ftype := ""
		if i_type != -1 and row.size() > i_type:
			ftype = row[i_type].strip_edges().to_lower()
		if not wanted.is_empty() and not wanted.has(ftype):
			result["filtered"] += 1
			continue

		var sig_name := ""
		if i_sig != -1 and row.size() > i_sig:
			sig_name = row[i_sig].strip_edges()
		if sig_name.is_empty() or sig_name.to_lower() in ["n/a", "none", "null"]:
			sig_name = "MalwareBazaar.%s" % (ftype if not ftype.is_empty() else "Unknown")

		match add_hash(row[i_sha], sig_name, MB_SOURCE):
			OK:
				result["added"] += 1
			ERR_ALREADY_EXISTS:
				result["skipped"] += 1
			_:
				result["invalid"] += 1

	f.close()
	if i_sha == -1:
		return ERR_FILE_UNRECOGNIZED   # never found a sha256_hash column
	return OK


func _mb_load_auth_key() -> String:
	var cfg := ConfigFile.new()
	if cfg.load(SECRETS_PATH) != OK:
		return ""
	return str(cfg.get_value("malware_bazaar", "malware_bazaar_auth_key", "")).strip_edges()


func _mb_set_last_pull_time(full: bool, unix_time: int) -> void:
	var cfg := ConfigFile.new()
	cfg.load(PULL_STATE_PATH)  # fine if it doesn't exist yet
	cfg.set_value("malware_bazaar", "last_pull_full_unix" if full else "last_pull_recent_unix", unix_time)
	var err := cfg.save(PULL_STATE_PATH)
	if err != OK:
		push_warning("could not save pull timestamp: %s" % error_string(err))


func _mb_cleanup_tmp() -> void:
	for p in [MB_TMP_DOWNLOAD, MB_TMP_CSV]:
		if FileAccess.file_exists(p):
			DirAccess.remove_absolute(ProjectSettings.globalize_path(p))


func _mb_fail(result: Dictionary, err: Error, msg: String) -> Dictionary:
	result["error"] = err
	result["message"] = msg
	return result


# ---------------------------------------------------------------------------
# Internals: hash table
# ---------------------------------------------------------------------------

## Smallest power-of-two slot count that keeps load <= 50% for n entries.
static func _capacity_for(n: int) -> int:
	var cap := INITIAL_CAPACITY
	while n * 10 > cap * 5:
		cap *= 2
	return cap


## Slot index for a hex hash, or -1 if it's malformed or not in the DB.
func _slot_of(hex: String) -> int:
	var normalized := normalize_hash(hex)
	if normalized.is_empty():
		return -1
	return _find_slot(normalized.hex_decode())


## Slot index holding this hash, or -1. raw = 32 bytes.
func _find_slot(raw: PackedByteArray) -> int:
	var key := raw.decode_u32(0)
	var i := key & _mask
	for _step in _capacity:
		var e := _slots[i]
		if e == SLOT_EMPTY:
			return -1
		# cheap 4-byte compare first, full 32-byte compare only on a prefix match
		if e >= 0 and _hashes.decode_u32(e * HASH_BYTES) == key \
				and _hashes.slice(e * HASH_BYTES, (e + 1) * HASH_BYTES) == raw:
			return i
		i = (i + 1) & _mask
	return -1


## Returns true if added, false if the hash was already present. raw = 32 bytes.
func _add_raw(raw: PackedByteArray, sig_name: String, source: String, added: int) -> bool:
	if _find_slot(raw) != -1:
		return false

	# Keep load <= 60% (counting tombstones) so probe chains stay short
	if (_used + 1) * 10 > _capacity * 6:
		_rebuild_slots(_capacity_for(_count + 1))

	var e := _names.size()
	_hashes.append_array(raw)
	_names.append(_intern(sig_name))
	_sources.append(_intern(source))
	_added.append(added)

	var i := raw.decode_u32(0) & _mask
	while _slots[i] >= 0:
		i = (i + 1) & _mask
	if _slots[i] == SLOT_EMPTY:
		_used += 1
	_slots[i] = e
	_count += 1
	return true


## Rebuilds the slot table at the given capacity (dropping all tombstones).
## Compacts removed entries out of the arrays first.
func _rebuild_slots(cap: int) -> void:
	if _dead > 0:
		_compact_entries()

	var n := _names.size()
	var mask := cap - 1
	var slots := PackedInt32Array()
	slots.resize(cap)
	slots.fill(SLOT_EMPTY)

	for e in n:
		var i := _hashes.decode_u32(e * HASH_BYTES) & mask
		while slots[i] != SLOT_EMPTY:
			i = (i + 1) & mask
		slots[i] = e

	_slots = slots
	_capacity = cap
	_mask = mask
	_used = n


## Throws away removed entries. Invalidates _slots; callers must rebuild them.
func _compact_entries() -> void:
	var hashes := PackedByteArray()
	var names := PackedInt32Array()
	var sources := PackedInt32Array()
	var added := PackedInt64Array()
	for e in _names.size():
		if _names[e] == NAME_DEAD:
			continue
		hashes.append_array(_hashes.slice(e * HASH_BYTES, (e + 1) * HASH_BYTES))
		names.append(_names[e])
		sources.append(_sources[e])
		added.append(_added[e])
	_hashes = hashes
	_names = names
	_sources = sources
	_added = added
	_dead = 0


func _intern(s: String) -> int:
	var id: int = _string_ids.get(s, -1)
	if id == -1:
		id = _strings.size()
		_strings.append(s)
		_string_ids[s] = id
	return id


func _string_at(idx: int) -> String:
	if idx >= 0 and idx < _strings.size():
		return _strings[idx]
	return ""


# ---------------------------------------------------------------------------
# NOTE ON TAMPER PROTECTION
# The trailing checksum only catches accidental corruption: anyone who can
# edit the file can recompute it. Once you add real updates, ship a detached
# signature (e.g. Ed25519/RSA via Godot's Crypto class: Crypto.sign /
# Crypto.verify with a public key embedded in your app) and verify it before
# loading a downloaded database.
# ---------------------------------------------------------------------------
