extends RefCounted
class_name SuspiciousStringDetector

# Maximum file size to scan (500 MB).
# This prevents loading excessively large files into memory.
var max_file_size_bytes: int = 500 * 1024 * 1024

# Suspicious strings grouped by category.
const SUSPICIOUS_STRINGS: Dictionary = {
	"Command Execution": [
		"Invoke-Expression",
		"IEX(",
		"IEX ",
		"cmd.exe /c",
		"powershell -enc",
		"powershell.exe -enc",
		"Start-Process",
		"ShellExecute",
		"WinExec"
	],

	"Download / Network": [
		"DownloadString",
		"DownloadFile",
		"Invoke-WebRequest",
		"Invoke-RestMethod",
		"WebClient",
		"curl ",
		"wget "
	],

	"Obfuscation": [
		"FromBase64String",
		"ToBase64String",
		"base64 -d",
		"base64 --decode"
	],

	"Persistence": [
		"CurrentVersion\\Run",
		"CurrentVersion\\RunOnce",
		"schtasks /create",
		"sc.exe create",
		"Startup"
	],

	"Process Manipulation": [
		"CreateRemoteThread",
		"WriteProcessMemory",
		"VirtualAllocEx",
		"OpenProcess",
		"NtUnmapViewOfSection"
	],

	"Destructive Commands": [
		"format c:",
		"diskpart",
		"vssadmin delete shadows",
		"wbadmin delete catalog",
		"rm -rf",
		"shred"
	]
}

# Regex patterns for indicators that have variable values.
const SUSPICIOUS_PATTERNS: Dictionary = {
	"URL": [
		r"https?://[^\s\"'<>]+"
	],

	"IPv4 Address": [
		r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
	]
}


func scan_file(file_path: String) -> Dictionary:
	var result: Dictionary = {
		"file_path": file_path,
		"success": false,
		"findings": [],
		"error": ""
	}

	# Verify that the file exists.
	if not FileAccess.file_exists(file_path):
		result["error"] = "File does not exist."
		return result

	# Open the file.
	var file := FileAccess.open(file_path, FileAccess.READ)

	if file == null:
		result["error"] = "Unable to open file: " + error_string(FileAccess.get_open_error())
		return result

	# Check file size before reading it.
	var file_size: int = file.get_length()

	if file_size > max_file_size_bytes:
		file.close()
		result["error"] = "File exceeds the maximum scan size."
		return result

	# Read file contents.
	var file_bytes: PackedByteArray = file.get_buffer(file_size)
	file.close()

	# Convert file contents into a string for analysis.
	# This allows us to search for ASCII strings inside binaries.
	var file_text: String = file_bytes.get_string_from_ascii()

	# Case-insensitive search.
	var searchable_text: String = file_text.to_lower()

	# Search for suspicious strings.
	for category: String in SUSPICIOUS_STRINGS:
		for indicator: String in SUSPICIOUS_STRINGS[category]:
			var indicator_lower: String = indicator.to_lower()

			if searchable_text.contains(indicator_lower):
				result["findings"].append({
					"type": "String",
					"category": category,
					"indicator": indicator,
					"severity": _get_severity(category)
				})

	# Search for regular expression patterns.
	for category: String in SUSPICIOUS_PATTERNS:
		for pattern: String in SUSPICIOUS_PATTERNS[category]:
			var regex := RegEx.new()
			var compile_error: Error = regex.compile(pattern)

			if compile_error != OK:
				continue

			var matches: Array[RegExMatch] = regex.search_all(file_text)

			for regex_match: RegExMatch in matches:
				result["findings"].append({
					"type": "Pattern",
					"category": category,
					"indicator": regex_match.get_string(),
					"severity": _get_severity(category)
				})

	result["success"] = true
	return result


func _get_severity(category: String) -> String:
	match category:
		"Destructive Commands":
			return "High"

		"Process Manipulation":
			return "High"

		"Persistence":
			return "Medium"

		"Command Execution":
			return "Medium"

		"Obfuscation":
			return "Medium"

		"Download / Network":
			return "Medium"

		"URL":
			return "Low"

		"IPv4 Address":
			return "Low"

		_:
			return "Low"
			
func check_strings(file_path: String) -> String:
	var result: Dictionary = scan_file(file_path)
	if not result["success"]:
		return "Scan failed: " + result["error"] + "\n"


	if result["findings"].is_empty():
		return "No suspicious strings detected. \n"

	var msg:String
	msg += "Suspicious strings detected!"

	for finding: Dictionary in result["findings"]:
		msg += "" + finding["category"] + " | " + finding["severity"] + " | " + finding["indicator"]  
		
	return msg + "\n"
