extends GutTest

var _store: SignatureStore
var _db_path := ""


func before_each() -> void:
	_store = SignatureStore.new(false)
	_db_path = "user://gut_signature_store_%d_%d.vhdb" % [OS.get_process_id(), Time.get_ticks_usec()]


func after_each() -> void:
	_remove_path(_db_path)
	_remove_path(_db_path + ".tmp")


func test_add_lookup_duplicate_and_remove() -> void:
	var hash := "a".repeat(64)
	assert_eq(_store.add_hash(hash, "Example", "unit-test", 123), OK)
	assert_eq(_store.add_hash(hash, "Duplicate"), ERR_ALREADY_EXISTS)
	assert_true(_store.has_hash(hash))
	assert_eq(_store.lookup(hash), {"name": "Example", "source": "unit-test", "added": 123})

	assert_true(_store.remove_hash(hash))
	assert_false(_store.has_hash(hash))
	assert_eq(_store.size(), 0)


func test_read_only_store_and_malformed_hash_are_rejected() -> void:
	var read_only := SignatureStore.new()
	assert_eq(read_only.add_hash("b".repeat(64), "Example"), ERR_UNAUTHORIZED)
	assert_eq(_store.add_hash("short", "Example"), ERR_INVALID_PARAMETER)
	assert_eq(_store.size(), 0)


func test_save_and_load_round_trip_preserves_entry() -> void:
	var hash := "c".repeat(64)
	assert_eq(_store.add_hash(hash, "Saved signature", "test", 456), OK)
	assert_eq(_store.save_db(_db_path), OK)

	var loaded := SignatureStore.new()
	assert_eq(loaded.load_db(_db_path), OK)
	assert_eq(loaded.lookup(hash), {"name": "Saved signature", "source": "test", "added": 456})


func _remove_path(path: String) -> void:
	if FileAccess.file_exists(path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(path))
