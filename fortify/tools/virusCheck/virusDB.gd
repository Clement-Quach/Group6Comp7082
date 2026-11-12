class_name virusDB
extends RefCounted
## Black box for ALL signature data. virusCheck only talks to this class.
##
## It owns three databases (all stored in user://dbs/):
##   official   downloaded from GitHub (MalwareBazaar), read-only
##   user       hashes the user flagged themselves
##   whitelist  hashes the user trusts; wins over BOTH of the above
##
## Check order in classify(): whitelist -> user -> official.
## A hash lives in at most one of user / whitelist: the latest action wins.
##
## Updating the official database: NOTHING runs automatically. Call
## update_official() and `await` it (any Node inside the scene tree is the host):
##
##     var r: Dictionary = await db.update_official(self)
##     # r = {error, message, updated, local_version, remote_version}
##
## How the version check works: the GitHub Action publishes a tiny version.json
## next to each build. We download only that (~150 bytes), compare its "version"
## (unix time of the build) with the one we installed, and only fetch the big
## database file when they differ. The repository MUST be public.
##
## The storage engine (hash table, file format, load/save) is the inner class
## SignatureStore at the bottom of this file.

enum Verdict { CLEAN, WHITELISTED, USER, OFFICIAL }

const REPO_OWNER := "RyanC1"
const REPO_NAME := "malware-hash-db"
const RELEASE_TAG := "db-latest"
const MANIFEST_NAME := "version.json"

const DB_DIR := "user://dbs"
const OFFICIAL_PATH := "user://dbs/official.vhdb"
const USER_PATH := "user://dbs/user.vhdb"
const WHITELIST_PATH := "user://dbs/whitelist.vhdb"
const TMP_PATH := "user://dbs/official.download"
const STATE_PATH := "user://dbs/official_state.cfg"

const MANIFEST_TIMEOUT := 30.0
const DOWNLOAD_TIMEOUT := 900.0

var _official := SignatureStore.new()
var _user := SignatureStore.new()
var _whitelist := SignatureStore.new()
var _busy := false


func _init() -> void:
	_official.read_only = true
	_load(_official, OFFICIAL_PATH, "official")
	_load(_user, USER_PATH, "user")
	_load(_whitelist, WHITELIST_PATH, "whitelist")


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------

## Combines the three databases. Returns {"verdict": Verdict}, plus
## "name" / "source" / "added" when the verdict is USER or OFFICIAL.
func classify(hex: String) -> Dictionary:
	if _whitelist.has_hash(hex):
		return {"verdict": Verdict.WHITELISTED}

	var hit := _user.lookup(hex)
	if not hit.is_empty():
		hit["verdict"] = Verdict.USER
		return hit

	hit = _official.lookup(hex)
	if not hit.is_empty():
		hit["verdict"] = Verdict.OFFICIAL
		return hit

	return {"verdict": Verdict.CLEAN}


# ---------------------------------------------------------------------------
# Editing the user database and the whitelist (saved to disk immediately)
# ---------------------------------------------------------------------------

## Returns OK, ERR_INVALID_PARAMETER (bad hash) or ERR_ALREADY_EXISTS.
func add_user_hash(hex: String, sig_name: String = "UserAdded") -> Error:
	var err := _user.add_hash(hex, sig_name, "user")
	if err != OK and err != ERR_ALREADY_EXISTS:
		return err
	# flagging something means it can't also be trusted
	if _whitelist.remove_hash(hex):
		_whitelist.save_db(WHITELIST_PATH)
	if err == OK:
		var save_err := _user.save_db(USER_PATH)
		if save_err != OK:
			return save_err
	return err


## Returns OK, ERR_INVALID_PARAMETER (bad hash) or ERR_ALREADY_EXISTS.
func add_whitelist_hash(hex: String, sig_name: String = "Whitelisted") -> Error:
	var err := _whitelist.add_hash(hex, sig_name, "user")
	if err != OK and err != ERR_ALREADY_EXISTS:
		return err
	# trusting something means it can't also be in the user's malware list
	if _user.remove_hash(hex):
		_user.save_db(USER_PATH)
	if err == OK:
		var save_err := _whitelist.save_db(WHITELIST_PATH)
		if save_err != OK:
			return save_err
	return err


func remove_user_hash(hex: String) -> bool:
	if not _user.remove_hash(hex):
		return false
	_user.save_db(USER_PATH)
	return true


func remove_whitelist_hash(hex: String) -> bool:
	if not _whitelist.remove_hash(hex):
		return false
	_whitelist.save_db(WHITELIST_PATH)
	return true


# ---------------------------------------------------------------------------
# Info
# ---------------------------------------------------------------------------

## Signatures that can flag a file (official + user). The whitelist is separate.
func size() -> int:
	return _official.size() + _user.size()

func official_size() -> int:
	return _official.size()

func user_size() -> int:
	return _user.size()

func whitelist_size() -> int:
	return _whitelist.size()

## Unix time (= version number) of the installed official build, 0 if none.
func get_official_version() -> int:
	return int(_read_state("version", 0))

func get_official_version_string() -> String:
	var v := get_official_version()
	if v == 0:
		return "never"
	return Time.get_datetime_string_from_unix_time(v, true) + " UTC"

## Unix time of the last successful version check against GitHub.
func get_last_check_time() -> int:
	return int(_read_state("last_check_unix", 0))


# ---------------------------------------------------------------------------
# Updating the official database from GitHub
# ---------------------------------------------------------------------------

## Checks GitHub, downloads and installs a newer official database if there is
## one. force = true re-downloads even if the version matches (or the sanity
## check below objects). The in-memory database is only replaced on success.
func update_official(host: Node, force: bool = false) -> Dictionary:
	var result := {
		"error": OK,
		"message": "",
		"updated": false,
		"local_version": get_official_version(),
		"remote_version": 0,
	}
	if host == null or not host.is_inside_tree():
		return _fail(result, ERR_UNCONFIGURED, "update_official needs a host node inside the scene tree")
	if _busy:
		return _fail(result, ERR_BUSY, "an update is already running")

	_busy = true
	var r := await _update_impl(host, force, result)
	_busy = false
	return r


func _update_impl(host: Node, force: bool, result: Dictionary) -> Dictionary:
	var m := await _fetch_manifest(host)
	if m["error"] != OK:
		return _fail(result, m["error"], m["message"])
	var manifest: Dictionary = m["manifest"]
	result["remote_version"] = manifest["version"]
	_write_state("last_check_unix", int(Time.get_unix_time_from_system()))

	# Up to date? (size 0 means we have nothing usable, so download anyway)
	if not force and _official.size() > 0 and manifest["version"] == get_official_version():
		result["message"] = "official database is up to date (%s)" % get_official_version_string()
		return result

	# Sanity check: the official database only ever grows. If a published build is
	# less than half the size of what we have, something went wrong on the server.
	# (If you later change FILE_TYPES in the workflow, use force = true once.)
	if not force and _official.size() > 1000 and int(manifest["count"]) < _official.size() / 2.0:
		return _fail(result, ERR_INVALID_DATA,
			"remote database has %d signatures but we already have %d, refusing to install it" % [manifest["count"], _official.size()])

	DirAccess.make_dir_recursive_absolute(ProjectSettings.globalize_path(DB_DIR))
	_cleanup_tmp()

	var dl := await _download(host, _url(manifest["file"]), TMP_PATH, DOWNLOAD_TIMEOUT)
	if dl["error"] != OK:
		_cleanup_tmp()
		return _fail(result, dl["error"], dl["message"])

	# Cheap truncation check, then load_db() validates the header, sizes and the
	# SHA-256 trailer. If it fails, the current in-memory database is untouched.
	if _file_size(TMP_PATH) != int(manifest["size"]):
		_cleanup_tmp()
		return _fail(result, ERR_FILE_CORRUPT, "downloaded file has the wrong size, try again later")
	var err := _official.load_db(TMP_PATH)
	if err != OK:
		_cleanup_tmp()
		return _fail(result, err, "downloaded database failed validation: %s" % error_string(err))

	# Valid and now live in memory: make it the copy on disk too.
	err = DirAccess.rename_absolute(
		ProjectSettings.globalize_path(TMP_PATH),
		ProjectSettings.globalize_path(OFFICIAL_PATH))
	if err != OK:
		_cleanup_tmp()
		return _fail(result, err, "database loaded but could not be saved to disk: %s" % error_string(err))

	_write_state("version", manifest["version"])
	_write_state("count", manifest["count"])
	result["updated"] = true
	result["local_version"] = manifest["version"]
	result["message"] = "official database updated to %s (%d signatures)" % [get_official_version_string(), _official.size()]
	return result


## Downloads and validates version.json. Returns {error, message, manifest}.
func _fetch_manifest(host: Node) -> Dictionary:
	var http := HTTPRequest.new()
	http.timeout = MANIFEST_TIMEOUT
	http.body_size_limit = 65536
	host.add_child(http)

	var err := http.request(_url(MANIFEST_NAME))
	if err != OK:
		http.queue_free()
		return {"error": err, "message": "could not start version check: %s" % error_string(err)}

	var resp: Array = await http.request_completed   # [result, code, headers, body]
	http.queue_free()

	var check := _check_response(resp[0], resp[1])
	if check["error"] != OK:
		return check

	var body: PackedByteArray = resp[3]
	var parsed = JSON.parse_string(body.get_string_from_utf8())
	if not (parsed is Dictionary):
		return {"error": ERR_PARSE_ERROR, "message": "version.json is not valid JSON"}
	for key in ["version", "file", "size", "count"]:
		if not parsed.has(key):
			return {"error": ERR_PARSE_ERROR, "message": "version.json is missing '%s'" % key}

	# The file name ends up in a URL, so only accept exactly what the Action produces
	var name_re := RegEx.create_from_string("^mb-[0-9]+\\.vhdb$")
	if name_re.search(str(parsed["file"])) == null:
		return {"error": ERR_INVALID_DATA, "message": "version.json has an unexpected file name"}

	return {"error": OK, "message": "", "manifest": {
		"version": int(parsed["version"]),
		"file": str(parsed["file"]),
		"size": int(parsed["size"]),
		"count": int(parsed["count"]),
	}}


## Streams a (possibly 100+ MB) file straight to disk.
func _download(host: Node, url: String, dest: String, timeout: float) -> Dictionary:
	var http := HTTPRequest.new()
	http.download_file = dest
	http.timeout = timeout
	http.use_threads = true
	host.add_child(http)

	var err := http.request(url)
	if err != OK:
		http.queue_free()
		return {"error": err, "message": "could not start download: %s" % error_string(err)}

	var resp: Array = await http.request_completed
	http.queue_free()
	return _check_response(resp[0], resp[1])


func _check_response(net_result: int, code: int) -> Dictionary:
	if net_result == HTTPRequest.RESULT_TIMEOUT:
		return {"error": ERR_TIMEOUT, "message": "request to GitHub timed out"}
	if net_result != HTTPRequest.RESULT_SUCCESS:
		return {"error": ERR_CANT_CONNECT, "message": "network error (HTTPRequest result %d)" % net_result}
	if code == 404:
		return {"error": ERR_FILE_NOT_FOUND,
			"message": "HTTP 404 from GitHub: check REPO_OWNER / REPO_NAME / RELEASE_TAG and that the repo is public and the Action has run"}
	if code != 200:
		return {"error": ERR_CANT_CONNECT, "message": "GitHub returned HTTP %d" % code}
	return {"error": OK, "message": ""}


func _url(file_name: String) -> String:
	return "https://github.com/%s/%s/releases/download/%s/%s" % [REPO_OWNER, REPO_NAME, RELEASE_TAG, file_name]


func _file_size(path: String) -> int:
	var f := FileAccess.open(path, FileAccess.READ)
	if f == null:
		return -1
	var n := f.get_length()
	f.close()
	return n


func _cleanup_tmp() -> void:
	if FileAccess.file_exists(TMP_PATH):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(TMP_PATH))


func _read_state(key: String, default: Variant) -> Variant:
	var cfg := ConfigFile.new()
	if cfg.load(STATE_PATH) != OK:
		return default
	return cfg.get_value("official", key, default)


func _write_state(key: String, value: Variant) -> void:
	var cfg := ConfigFile.new()
	cfg.load(STATE_PATH)   # fine if it doesn't exist yet
	cfg.set_value("official", key, value)
	var err := cfg.save(STATE_PATH)
	if err != OK:
		push_warning("could not save updater state: %s" % error_string(err))


func _fail(result: Dictionary, err: Error, msg: String) -> Dictionary:
	result["error"] = err
	result["message"] = msg
	return result


func _load(db: SignatureStore, path: String, label: String) -> void:
	var err := db.load_db(path)
	match err:
		OK:
			print("Loaded %d %s signatures" % [db.size(), label])
		ERR_FILE_NOT_FOUND:
			print("No %s database yet, starting empty" % label)
		_:
			push_error("Failed to load %s DB: %s" % [label, error_string(err)])


# ===========================================================================
# Storage engine: one compact SHA-256 signature database (used 3 times above)
# ===========================================================================

class SignatureStore:
	## Compact SHA-256 signature database, built to hold millions of hashes.
	##
	## In memory (struct-of-arrays, ~57 bytes per signature instead of the several
	## hundred a Dictionary-of-Dictionaries needs):
	##   _hashes   PackedByteArray   32 raw bytes per entry
	##   _names    PackedInt32Array  index into the shared string table
	##   _sources  PackedInt32Array  index into the shared string table
	##   _added    PackedInt64Array  unix time
	##   _slots    PackedInt32Array  open-addressing hash table -> entry index
	##   _strings  PackedStringArray every distinct name/source
	##
	## On disk (little-endian, raw arrays so load/save are bulk I/O with no
	## per-entry parsing):
	##   "VHDB" | u32 version | u32 count | u32 capacity | u32 strtab_len
	##   string table (u32 n, then n x length-prefixed string)
	##   count x 32 B hashes | count x i32 names | count x i32 sources | count x i64 added
	##   capacity x i32 slot table
	##   32 bytes SHA-256 of everything above


	# user:// (res:// is read-only in an exported game). Callers normally pass their own path.
	const DB_PATH := "user://dbs/default.vhdb"

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

	## When true, add_hash / remove_hash / save_db refuse to work. load_db still does.
	var read_only := false


	func _init() -> void:
		_rebuild_slots(INITIAL_CAPACITY)


	# ---------------------------------------------------------------------------
	# Signatures: add / remove / lookup
	# ---------------------------------------------------------------------------

	## Add a hash directly (hex string). Returns OK, ERR_INVALID_PARAMETER if the
	## hash is malformed, or ERR_ALREADY_EXISTS if it's already in the DB.
	func add_hash(hex: String, sig_name: String, source: String = "manual", added_unix: int = -1) -> Error:
		if read_only:
			return ERR_UNAUTHORIZED
		var normalized := _normalize_hash(hex)
		if normalized.is_empty():
			return ERR_INVALID_PARAMETER
		if added_unix < 0:
			added_unix = int(Time.get_unix_time_from_system())
		if not _add_raw(normalized.hex_decode(), sig_name, source, added_unix):
			return ERR_ALREADY_EXISTS
		return OK


	func remove_hash(hex: String) -> bool:
		if read_only:
			return false
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

	func size() -> int:
		return _count


	# ---------------------------------------------------------------------------
	# Persistence
	# ---------------------------------------------------------------------------

	func save_db(path: String = DB_PATH) -> Error:
		if read_only:
			return ERR_UNAUTHORIZED
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
		var normalized := _normalize_hash(hex)
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

	static func _normalize_hash(hex: String) -> String:
		var h := hex.strip_edges().to_lower()
		if h.length() != HASH_BYTES * 2 or not h.is_valid_hex_number(false):
			return ""
		return h
