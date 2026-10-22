class_name HashGenerator
extends RefCounted

enum HashAlgorithm {
	SHA1,
	SHA256,
	MD5,
	INVALID
}

static func generate_hash(file_path: String, algorithm_name: String = "sha256") -> String:
	var algo_type = _parse_algorithm(algorithm_name)
	
	if algo_type == HashAlgorithm.INVALID:
		print("HashGenerator Error: Unrecognized algorithm name -> '", algorithm_name, "'")
		return ""
	
	if not FileAccess.file_exists(file_path):
		print("HashGenerator Error: File not found at -> ", file_path)
		return ""
		
	var file = FileAccess.open(file_path, FileAccess.READ)
	if not file:
		print("HashGenerator Error: Failed to open file -> ", file_path)
		return ""
		
	var ctx = HashingContext.new()
	var crypto_type = _get_crypto_hash_type(algo_type)
	
	var err = ctx.start(crypto_type)
	if err != OK:
		print("HashGenerator Error: Failed to start hashing context. Error: ", err)
		print("  -> algorithm_name: '", algorithm_name, "' | parsed algo: ", algo_type, " | crypto_type: ", crypto_type)
		return ""
		
	const CHUNK_SIZE = 4096
	while not file.eof_reached():
		var chunk = file.get_buffer(CHUNK_SIZE)
		if chunk.size() > 0:
			ctx.update(chunk)
			
	var hash_bytes = ctx.finish()
	return hash_bytes.hex_encode()

static func _parse_algorithm(algo_str: String) -> HashAlgorithm:
	# Normalize: lowercase, remove hyphens and spaces
	var normalized = algo_str.to_lower().replace("-", "").replace(" ", "").strip_edges()
	
	match normalized:
		"sha1":
			return HashAlgorithm.SHA1
		"sha256":
			return HashAlgorithm.SHA256
		"md5":
			return HashAlgorithm.MD5
		_:
			return HashAlgorithm.INVALID

static func _get_crypto_hash_type(algo: HashAlgorithm) -> HashingContext.HashType:
	match algo:
		HashAlgorithm.SHA1:
			return HashingContext.HASH_SHA1
		HashAlgorithm.MD5:
			return HashingContext.HASH_MD5
		HashAlgorithm.SHA256:
			return HashingContext.HASH_SHA256
		_:
			return HashingContext.HASH_SHA256 # Fallback only for safety
