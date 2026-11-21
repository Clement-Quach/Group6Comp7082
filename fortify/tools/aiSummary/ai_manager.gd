extends Node
class_name AIManager

const API_URL := "https://api.groq.com/openai/v1/chat/completions"
const MODEL := "openai/gpt-oss-120b" 
const SECRETS_PATH := "res://secrets.cfg"

const CHAT_SYSTEM := "You are a helpful assistant inside Fortify, an antivirus app. Keep answers short."
const REPORT_SYSTEM := """
You are a security analyst inside an antivirus application called Fortify.

Generate a security report based on the provided network and port scan results.

The report must contain these sections, each title on its own line:

Summary
Findings
Risk Level
Recommended Actions

Instructions:
- Only use information provided in the scan results.
- Never invent devices, IP addresses, open ports, vulnerabilities, or threats.
- Explain potentially concerning findings without automatically classifying them as threats.
- An open port does not necessarily indicate a vulnerability.
- Distinguish between confirmed findings and potential security concerns.
- If no concerning findings exist, state that.
- If the scan failed or returned incomplete information, mention this.
- Assign a risk level of low, medium, or high based on the available evidence.
- Keep the report concise and professional.
- Plain text only, no markdown.
"""
const MAX_LOG_CHARS := 8000


## Sends a prompt to Groq and returns the reply (or an error message).
func ask(prompt: String, system_prompt: String = CHAT_SYSTEM) -> String:
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
			{"role": "system", "content": system_prompt},
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

# Sends the scan results to ai to generate the report
func generateReport(log_text: String) -> String:
	if log_text.strip_edges().is_empty():
		return "The scan log is empty. Run a scan first."
	# check if the scan results text file goes over the maximum characters for log,
	# if so get the newest ones and truncate the rest
	if log_text.length() > MAX_LOG_CHARS:
		log_text = log_text.substr(log_text.length() - MAX_LOG_CHARS)  # keep newest
	return await ask(log_text, REPORT_SYSTEM)


# Get the api key from the secrets.cfg file
func _load_api_key() -> String:
	var key := OS.get_environment("GROQ_API_KEY")
	if not key.is_empty():
		return key
	var cfg := ConfigFile.new()
	if cfg.load(SECRETS_PATH) == OK:
		return cfg.get_value("groq", "api_key", "")
	return ""
