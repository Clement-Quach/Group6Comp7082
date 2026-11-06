extends Node
class_name AIManager

const API_URL := "https://api.groq.com/openai/v1/chat/completions"
const MODEL := "llama-3.3-70b-versatile"
const SECRETS_PATH := "res://secrets.cfg"

var http: HTTPRequest

# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	http = HTTPRequest.new()
	http.timeout = 30
	add_child(http)


## Sends a prompt to Groq and returns the reply (or an error message).
func ask(prompt: String) -> String:
	var key := _load_api_key()
	if key.is_empty():
		return "AI unavailable: copy secrets.example.cfg to secrets.cfg and add your Groq key"

	# the body that will be sent to the ai
	# includes the roles of the system and the user
	var body := {
		"model": MODEL,
		"messages": [
			{"role": "system", "content": "You are a helpful assistant inside Fortify, an antivirus app. Keep answers short."},
			{"role": "user", "content": prompt},
		],
	}
	var headers := [
		"Content-Type: application/json",
		"Authorization: Bearer " + key,
	]
	var err := http.request(API_URL, headers, HTTPClient.METHOD_POST, JSON.stringify(body))
	if err != OK:
		return "Request failed to start: %s" % error_string(err)
 
	# pause the function until the http request is finished and gets the results of the http request
	var response: Array = await http.request_completed
	# result of the network request
	var result: int = response[0]
	# HTTP status code
	var code: int = response[1]
	# the body of the response as raw bytes
	var raw: PackedByteArray = response[3]

	if result != HTTPRequest.RESULT_SUCCESS:
		return "Network error (code %d)" % result
	if code != 200:
		return "Groq returned HTTP %d" % code  # 401 = bad key, 429 = rate limited

	var data = JSON.parse_string(raw.get_string_from_utf8())
	if not (data is Dictionary) or not data.has("choices"):
		return "Unexpected response from Groq"

	return str(data["choices"][0]["message"]["content"]).strip_edges()

# get the api key from the secrets.cfg file
func _load_api_key() -> String:
	var key := OS.get_environment("GROQ_API_KEY")
	if not key.is_empty():
		return key
	var cfg := ConfigFile.new()
	if cfg.load(SECRETS_PATH) == OK:
		return cfg.get_value("groq", "api_key", "")
	return ""
	
