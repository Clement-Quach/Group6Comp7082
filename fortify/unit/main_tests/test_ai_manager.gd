extends GutTest

# Override ask() so these tests never read a key or call the Groq API.
class FakeAIManager:
	extends AIManager
	var calls := 0
	var received_prompt := ""
	var received_system_prompt := ""

	func ask(prompt: String, system_prompt: String = "") -> String:
		calls += 1
		received_prompt = prompt
		received_system_prompt = system_prompt
		return "fake response"


func test_empty_report_input_returns_without_calling_ai() -> void:
	var ai := FakeAIManager.new()
	add_child(ai)

	var result: String = await ai.generateReport("  \n ")

	assert_eq(result, "The scan log is empty. Run a scan first.")
	assert_eq(ai.calls, 0)
	ai.free()


func test_long_report_keeps_only_the_newest_8000_characters() -> void:
	var ai := FakeAIManager.new()
	add_child(ai)
	var scan_log := "x".repeat(AIManager.MAX_LOG_CHARS + 25)

	var result: String = await ai.generateReport(scan_log)

	assert_eq(result, "fake response")
	assert_eq(ai.calls, 1)
	assert_eq(ai.received_prompt, scan_log.substr(25))
	assert_eq(ai.received_prompt.length(), AIManager.MAX_LOG_CHARS)
	assert_eq(ai.received_system_prompt, AIManager.REPORT_SYSTEM)
	ai.free()
