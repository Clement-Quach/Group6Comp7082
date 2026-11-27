class_name virusDB
extends Node
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
## The storage engine (hash table, file format, load/save) is SignatureStore.

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
var _user := SignatureStore.new(false)
var _whitelist := SignatureStore.new(false)
var _busy := false


func _init() -> void:
	_official.read_only = true
	_load(_official, OFFICIAL_PATH, "official")
	_load(_user, USER_PATH, "user")
	_load(_whitelist, WHITELIST_PATH, "whitelist")


## Combines the three databases. Returns {"verdict": Verdict}, plus
## "name" / "source" / "added" when the verdict is USER or OFFICIAL.
func classify(hex: String) -> Dictionary:
	var hit := _whitelist.lookup(hex)
	if not hit.is_empty():
		hit["verdict"] = Verdict.WHITELISTED
		return hit

	hit = _user.lookup(hex)
	if not hit.is_empty():
		hit["verdict"] = Verdict.USER
		return hit

	hit = _official.lookup(hex)
	if not hit.is_empty():
		hit["verdict"] = Verdict.OFFICIAL
		return hit

	return {"verdict": Verdict.CLEAN}


## Returns OK, ERR_INVALID_PARAMETER (bad hash) or ERR_ALREADY_EXISTS.
func add_user_hash(hex: String, sig_name: String = "UserAdded") -> Error:
	return _add_exclusive(_user, USER_PATH, hex, sig_name)


## Returns OK, ERR_INVALID_PARAMETER (bad hash) or ERR_ALREADY_EXISTS.
func add_whitelist_hash(hex: String, sig_name: String = "Whitelisted") -> Error:
	return _add_exclusive(_whitelist, WHITELIST_PATH, hex, sig_name)


func remove_user_hash(hex: String) -> bool:
	return _remove_and_save(_user, USER_PATH, hex)


func remove_whitelist_hash(hex: String) -> bool:
	return _remove_and_save(_whitelist, WHITELIST_PATH, hex)


func _add_exclusive(into: SignatureStore, into_path: String, hex: String, sig_name: String) -> Error:
	var err := into.add_hash(hex, sig_name, "user")
	return into.save_db(into_path) if err == OK else err


func _remove_and_save(db: SignatureStore, path: String, hex: String) -> bool:
	if not db.remove_hash(hex):
		return false
	db.save_db(path)
	return true

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
	if host == null or not host.is_inside_tree():
		return _result(ERR_UNCONFIGURED, "update_official needs a host node inside the scene tree")
	if _busy:
		return _result(ERR_BUSY, "an update is already running")

	_busy = true
	var r := await _update_impl(host, force)
	_busy = false
	_cleanup_tmp()   # no-op after a successful install (the file was renamed away)
	return r


func _update_impl(host: Node, force: bool) -> Dictionary:
	var m := await _fetch_manifest(host)
	if m["error"] != OK:
		return _result(m["error"], m["message"])
	var manifest: Dictionary = m["manifest"]
	var remote: int = manifest["version"]
	_write_state({"last_check_unix": int(Time.get_unix_time_from_system())})

	# Up to date? (size 0 means we have nothing usable, so download anyway)
	if not force and _official.size() > 0 and remote == get_official_version():
		return _result(OK, "official database is up to date (%s)" % get_official_version_string(), remote)

	# Sanity check: the official database only ever grows. If a published build is
	# less than half the size of what we have, something went wrong on the server.
	# (If you later change FILE_TYPES in the workflow, use force = true once.)
	if not force and _official.size() > 1000 and manifest["count"] < _official.size() / 2.0:
		return _result(ERR_INVALID_DATA,
			"remote database has %d signatures but we already have %d, refusing to install it" % [manifest["count"], _official.size()],
			remote)

	DirAccess.make_dir_recursive_absolute(ProjectSettings.globalize_path(DB_DIR))

	var dl := await _http_get(host, _url(manifest["file"]), DOWNLOAD_TIMEOUT, TMP_PATH)
	if dl["error"] != OK:
		return _result(dl["error"], dl["message"], remote)

	# Cheap truncation check, then load_db() validates the header, sizes and the
	# SHA-256 trailer. If it fails, the current in-memory database is untouched.
	if _file_size(TMP_PATH) != manifest["size"]:
		return _result(ERR_FILE_CORRUPT, "downloaded file has the wrong size, try again later", remote)
	var err := _official.load_db(TMP_PATH)
	if err != OK:
		return _result(err, "downloaded database failed validation: %s" % error_string(err), remote)

	# Valid and now live in memory: make it the copy on disk too.
	err = DirAccess.rename_absolute(
		ProjectSettings.globalize_path(TMP_PATH),
		ProjectSettings.globalize_path(OFFICIAL_PATH))
	if err != OK:
		return _result(err, "database loaded but could not be saved to disk: %s" % error_string(err), remote)

	_write_state({"version": remote, "count": manifest["count"]})
	return _result(OK, "official database updated to %s (%d signatures)" % [get_official_version_string(), _official.size()], remote, true)


## Downloads and validates version.json. Returns {error, message, manifest}.
func _fetch_manifest(host: Node) -> Dictionary:
	var r := await _http_get(host, _url(MANIFEST_NAME), MANIFEST_TIMEOUT)
	if r["error"] != OK:
		return r

	var parsed = JSON.parse_string(r["body"].get_string_from_utf8())
	if not (parsed is Dictionary) \
			or not ["version", "file", "size", "count"].all(func(k): return parsed.has(k)):
		return {"error": ERR_PARSE_ERROR, "message": "version.json is not valid or is missing fields"}

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


## GETs a URL. With `dest` it streams a (possibly 100+ MB) file straight to disk,
## otherwise the small response body is returned. Returns {error, message, body}.
func _http_get(host: Node, url: String, timeout: float, dest: String = "") -> Dictionary:
	var http := HTTPRequest.new()
	http.timeout = timeout
	if dest.is_empty():
		http.body_size_limit = 65536
	else:
		http.download_file = dest
		http.use_threads = true
	host.add_child(http)

	var err := http.request(url)
	if err != OK:
		http.queue_free()
		return {"error": err, "message": "could not start request: %s" % error_string(err)}

	var resp: Array = await http.request_completed   # [result, code, headers, body]
	http.queue_free()

	var check := _check_response(resp[0], resp[1])
	check["body"] = resp[3]
	return check


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


## Builds the dictionary update_official() returns. local_version is read live,
## so it is already the new version when called after a successful install.
func _result(err: Error, msg: String, remote_version: int = 0, updated: bool = false) -> Dictionary:
	return {
		"error": err,
		"message": msg,
		"updated": updated,
		"local_version": get_official_version(),
		"remote_version": remote_version,
	}


func _url(file_name: String) -> String:
	return "https://github.com/%s/%s/releases/download/%s/%s" % [REPO_OWNER, REPO_NAME, RELEASE_TAG, file_name]


func _file_size(path: String) -> int:
	var f := FileAccess.open(path, FileAccess.READ)
	return f.get_length() if f != null else -1


func _cleanup_tmp() -> void:
	if FileAccess.file_exists(TMP_PATH):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(TMP_PATH))


func _read_state(key: String, default: Variant) -> Variant:
	var cfg := ConfigFile.new()
	if cfg.load(STATE_PATH) != OK:
		return default
	return cfg.get_value("official", key, default)


func _write_state(values: Dictionary) -> void:
	var cfg := ConfigFile.new()
	cfg.load(STATE_PATH)   # fine if it doesn't exist yet
	for key in values:
		cfg.set_value("official", key, values[key])
	var err := cfg.save(STATE_PATH)
	if err != OK:
		push_warning("could not save updater state: %s" % error_string(err))


func _load(db: SignatureStore, path: String, label: String) -> void:
	var err := db.load_db(path)
	match err:
		OK:
			print("Loaded %d %s signatures" % [db.size(), label])
		ERR_FILE_NOT_FOUND:
			print("No %s database yet, starting empty" % label)
		_:
			push_error("Failed to load %s DB: %s" % [label, error_string(err)])