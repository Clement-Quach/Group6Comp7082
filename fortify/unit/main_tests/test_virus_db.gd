extends GutTest

# These are in-memory stores: the tests never call the database's save methods.
func test_classify_uses_whitelist_then_user_then_official_precedence() -> void:
	var database := _new_in_memory_database()
	var whitelist_hash := "a".repeat(64)
	var user_hash := "b".repeat(64)
	var official_hash := "c".repeat(64)

	database._official.add_hash(whitelist_hash, "Official copy", "official", 1)
	database._user.add_hash(whitelist_hash, "User copy", "user", 2)
	database._whitelist.add_hash(whitelist_hash, "Trusted copy", "user", 3)
	database._official.add_hash(user_hash, "Official copy", "official", 1)
	database._user.add_hash(user_hash, "User copy", "user", 2)
	database._official.add_hash(official_hash, "Official only", "official", 1)

	assert_eq(database.classify(whitelist_hash)["verdict"], virusDB.Verdict.WHITELISTED)
	assert_eq(database.classify(user_hash)["verdict"], virusDB.Verdict.USER)
	assert_eq(database.classify(official_hash)["verdict"], virusDB.Verdict.OFFICIAL)
	assert_eq(database.classify("d".repeat(64)), {"verdict": virusDB.Verdict.CLEAN})

	database.free()


func _new_in_memory_database() -> virusDB:
	var database := virusDB.new()
	database._official = SignatureStore.new(false)
	database._user = SignatureStore.new(false)
	database._whitelist = SignatureStore.new(false)
	return database
