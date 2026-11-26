extends RefCounted
class_name EntropyChecker


# Maximum file size to analyze (500 MB).
var max_file_size_bytes: int = 500 * 1024 * 1024

# Entropy thresholds.
var medium_entropy_threshold: float = 6.0
var high_entropy_threshold: float = 7.0


func analyze_file(file_path: String) -> Dictionary:
	var result: Dictionary = {
		"file_path": file_path,
		"success": false,
		"entropy": 0.0,
		"entropy_level": "Unknown",
		"file_size": 0,
		"error": ""
	}

	# Check if file exists.
	if not FileAccess.file_exists(file_path):
		result["error"] = "File does not exist."
		return result

	# Open the file.
	var file := FileAccess.open(file_path, FileAccess.READ)

	if file == null:
		result["error"] = "Unable to open file: " + error_string(FileAccess.get_open_error())
		return result

	# Get file size.
	var file_size: int = file.get_length()
	result["file_size"] = file_size

	# Reject files that are too large.
	if file_size > max_file_size_bytes:
		file.close()
		result["error"] = "File exceeds maximum analysis size."
		return result

	# Handle empty files.
	if file_size == 0:
		file.close()
		result["success"] = true
		result["entropy"] = 0.0
		result["entropy_level"] = "Empty"
		return result

	# Read the file as raw bytes.
	var data: PackedByteArray = file.get_buffer(file_size)

	# Check for read errors.
	var read_error: Error = file.get_error()
	file.close()

	if read_error != OK:
		result["error"] = "Failed to read file: " + error_string(read_error)
		return result

	if data.size() != file_size:
		result["error"] = "Incomplete file read."
		return result

	# Calculate entropy.
	var entropy: float = _calculate_entropy(data)

	result["entropy"] = entropy
	result["entropy_level"] = _classify_entropy(entropy)
	result["success"] = true

	return result


func _calculate_entropy(data: PackedByteArray) -> float:
	var data_size: int = data.size()

	if data_size == 0:
		return 0.0

	# Count occurrences of each possible byte value (0-255).
	var frequencies: Array[int] = []
	frequencies.resize(256)
	frequencies.fill(0)

	for byte_value: int in data:
		frequencies[byte_value] += 1

	# Calculate Shannon entropy.
	var entropy: float = 0.0

	for frequency: int in frequencies:
		if frequency == 0:
			continue

		var probability: float = float(frequency) / float(data_size)

		entropy -= probability * (log(probability) / log(2.0))

	return entropy


func _classify_entropy(entropy: float) -> String:
	if entropy >= high_entropy_threshold:
		return "High"

	if entropy >= medium_entropy_threshold:
		return "Medium"

	return "Low"

func check_entropy(file_path: String) -> String:
	var result: Dictionary = analyze_file(file_path)
	var msg:String
	if not result["success"]:
		msg =  "Entropy analysis failed: " + result["error"]
		return msg + "\n"

	msg += "Entropy: %.2f out of 8\n" % result["entropy"]
	msg += "Classification: %s" % result["entropy_level"]

	if result["entropy_level"] == "High":
		msg += "\n Warning: File has high entropy."
	return msg + "\n"
