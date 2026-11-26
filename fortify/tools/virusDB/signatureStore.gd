extends RefCounted
class_name SignatureStore
## Compact SHA-256 signature database
##
## In memory structure:
##   _hashes   PackedByteArray   32 raw bytes per entry
##   _names    PackedInt32Array  index into the string table
##   _sources  PackedInt32Array  index into the string table
##   _added    PackedInt64Array  unix time
##   _slots    PackedInt32Array  open-addressing hash table -> entry index
##   _strings  PackedStringArray every distinct name/source
##
## On disk structure (little-endian, format unchanged from version 2):
##   "VHDB" | u32 version | u32 count | u32 capacity | u32 strtab_len
##   string table (u32 n, then n x length-prefixed string)
##   count x 32 B hashes | count x i32 names | count x i32 sources | count x i64 added
##   capacity x i32 slot table
##   32 bytes SHA-256 of everything above


const MAGIC := "VHDB"
const VERSION := 2
const HASH_BYTES := 32
const HEADER_BYTES := 20
const INITIAL_CAPACITY := 1024

const SLOT_EMPTY := -1

var _hashes := PackedByteArray()
var _names := PackedInt32Array()
var _sources := PackedInt32Array()
var _added := PackedInt64Array()
var _slots := PackedInt32Array()
var _strings := PackedStringArray()
var _string_ids: Dictionary = {}   # String -> index in _strings

var _mask := INITIAL_CAPACITY - 1  # _slots.size() - 1, cached for the hot path

var read_only:bool

func _init(p_read_only:bool = true) -> void:
	read_only = p_read_only 
	_rebuild_slots(INITIAL_CAPACITY)


## Add a hash directly (hex string). Returns OK, ERR_INVALID_PARAMETER if the
## hash is malformed, or ERR_ALREADY_EXISTS if it's already in the DB.
func add_hash(hex: String, sig_name: String, source: String = "manual", added_unix: int = -1) -> Error:
	if read_only:
		return ERR_UNAUTHORIZED
	var raw := _to_raw(hex)
	if raw.is_empty():
		return ERR_INVALID_PARAMETER
	if _find_slot(raw) != -1:
		return ERR_ALREADY_EXISTS
	if added_unix < 0:
		added_unix = int(Time.get_unix_time_from_system())

	# Keep load <= 50% so probe chains stay short
	if (_names.size() + 1) * 2 > _slots.size():
		_rebuild_slots(_slots.size() * 2)

	var e := _names.size()
	_hashes.append_array(raw)
	_names.append(_intern(sig_name))
	_sources.append(_intern(source))
	_added.append(added_unix)

	var i := raw.decode_u32(0) & _mask
	while _slots[i] != SLOT_EMPTY:
		i = (i + 1) & _mask
	_slots[i] = e
	return OK


func remove_hash(hex: String) -> bool:
	if read_only:
		return false
	var slot := _slot_of(hex)
	if slot == -1:
		return false
	var e := _slots[slot]
	var last := _names.size() - 1
	_delete_slot(slot)
	if e != last:
		# Move the last entry into the hole so the arrays stay dense
		var last_raw := _hashes.slice(last * HASH_BYTES, (last + 1) * HASH_BYTES)
		_slots[_find_slot(last_raw)] = e
		for k in 4:
			_hashes.encode_u64(e * HASH_BYTES + k * 8, last_raw.decode_u64(k * 8))
		_names[e] = _names[last]
		_sources[e] = _sources[last]
		_added[e] = _added[last]
	_hashes.resize(last * HASH_BYTES)
	_names.resize(last)
	_sources.resize(last)
	_added.resize(last)
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
	return _names.size()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

func save_db(path: String) -> Error:
	if read_only:
		return ERR_UNAUTHORIZED

	var strtab_buf := StreamPeerBuffer.new()
	strtab_buf.put_u32(_strings.size())
	for s in _strings:
		strtab_buf.put_string(s)
	var strtab := strtab_buf.data_array

	var header := MAGIC.to_ascii_buffer()
	header.resize(HEADER_BYTES)
	header.encode_u32(4, VERSION)
	header.encode_u32(8, _names.size())
	header.encode_u32(12, _slots.size())
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
func load_db(path: String) -> Error:
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
	_mask = capacity - 1
	_strings = strings
	_string_ids = ids
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

## Validates a hex hash and decodes it to 32 raw bytes. Empty if malformed.
static func _to_raw(hex: String) -> PackedByteArray:
	var h := hex.strip_edges().to_lower()
	if h.length() != HASH_BYTES * 2:
		return PackedByteArray()
	return h.hex_decode()


## Slot index for a hex hash, or -1 if it's malformed or not in the DB.
func _slot_of(hex: String) -> int:
	var raw := _to_raw(hex)
	return _find_slot(raw) if not raw.is_empty() else -1


## Slot index holding this hash, or -1. raw = 32 bytes.
func _find_slot(raw: PackedByteArray) -> int:
	var key := raw.decode_u32(0)
	var i := key & _mask
	for _step in _slots.size():
		var e := _slots[i]
		if e == SLOT_EMPTY:
			return -1
		# cheap 4-byte compare first, full 32-byte compare only on a prefix match
		if _hashes.decode_u32(e * HASH_BYTES) == key \
				and _hashes.slice(e * HASH_BYTES, (e + 1) * HASH_BYTES) == raw:
			return i
		i = (i + 1) & _mask
	return -1


## Linear-probing delete without tombstones: walk the rest of the probe chain
## and shift back any entry whose home position lets it fill the hole.
func _delete_slot(i: int) -> void:
	var j := i
	for _step in _slots.size():
		j = (j + 1) & _mask
		var e := _slots[j]
		if e == SLOT_EMPTY:
			break
		var home := _hashes.decode_u32(e * HASH_BYTES) & _mask
		if ((j - home) & _mask) >= ((j - i) & _mask):
			_slots[i] = e
			i = j
	_slots[i] = SLOT_EMPTY


## Rebuilds the slot table at the given capacity (a power of two).
func _rebuild_slots(cap: int) -> void:
	var mask := cap - 1
	var slots := PackedInt32Array()
	slots.resize(cap)
	slots.fill(SLOT_EMPTY)

	for e in _names.size():
		var i := _hashes.decode_u32(e * HASH_BYTES) & mask
		while slots[i] != SLOT_EMPTY:
			i = (i + 1) & mask
		slots[i] = e

	_slots = slots
	_mask = mask


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