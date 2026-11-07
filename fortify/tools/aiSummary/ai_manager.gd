extends Node
class_name AIManager

const API_URL := "https://api.groq.com/openai/v1/chat/completions"
const MODEL := "openai/gpt-oss-120b" 
const SECRETS_PATH := "res://secrets.cfg"


## Sends a prompt to Groq and returns the reply (or an error message).
func ask(prompt: String) -> String:
	var key := _load_api_key()
	if key.is_empty():
		return "AI unavailable: copy secrets.example.cfg to secrets.cfg and add your Groq key"

	# 1. Create a dynamic HTTPRequest node per request to prevent cross-talk/corrupted calls
	var http_request = HTTPRequest.new()
	add_child(http_request)
	http_request.timeout = 30

	var body := {
		"model": MODEL,
		"messages": [
			{"role": "system", "content": "You are a helpful assistant inside Fortify, an antivirus app. Keep answers short."},
			{"role": "user", "content": prompt},
		],
	}
	
	# 2. Added a standard User-Agent header to ensure API gateway compliance
	var headers := [
		"Content-Type: application/json",
		"Authorization: Bearer " + key,
		"User-Agent: GodotEngine/4.x" 
	]
	
	var err := http_request.request(API_URL, headers, HTTPClient.METHOD_POST, JSON.stringify(body))
	if err != OK:
		http_request.queue_free() # Clean up node
		return "Request failed to start: %s" % error_string(err)
 
	var response: Array = await http_request.request_completed
	
	# Clean up the node immediately after receiving data
	http_request.queue_free()

	var result: int = response[0]
	var code: int = response[1]
	var raw: PackedByteArray = response[3]

	if result != HTTPRequest.RESULT_SUCCESS:
		return "Network error (code %d)" % result
		
	# Catching the exact 404 response debug text from Groq
	if code != 200:
		var err_body = raw.get_string_from_utf8()
		return "Groq returned HTTP %d: %s" % [code, err_body]

	var data = JSON.parse_string(raw.get_string_from_utf8())
	if not (data is Dictionary) or not data.has("choices"):
		return "Unexpected response from Groq"

	return str(data["choices"][0]["message"]["content"]).strip_edges()


# Get the api key from the secrets.cfg file
func _load_api_key() -> String:
	var key := OS.get_environment("GROQ_API_KEY")
	if not key.is_empty():
		return key
	var cfg := ConfigFile.new()
	if cfg.load(SECRETS_PATH) == OK:
		return cfg.get_value("groq", "api_key", "")
	return ""
