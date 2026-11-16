extends Node
class_name NetworkScanner


func get_arp_table() -> String:
	var output = []
	var command: String
	var args: PackedStringArray

	match OS.get_name():
		"Windows":
			command = "arp"
			args = ["-a"]

		"Linux":
			command = "ip"
			args = ["neigh"]

		_:
			return "Unsupported operating system"

	var exit_code = OS.execute(command, args, output)

	if exit_code != 0:
		return "Failed to retrieve ARP table"

	if output.is_empty():
		return "No devices found"

	GlobalLogger.resultLog("ARP scan result: \n"+output[0])
	return output[0]

func get_open_ports() -> String:
	var output = []
	var command: String
	var args: PackedStringArray

	match OS.get_name():
		"Windows":
			command = "netstat"
			args = ["-ano"]

		"Linux":
			command = "ss"
			args = ["-tulnp"]

		_:
			return "Unsupported operating system"

	var exit_code = OS.execute(command, args, output)

	if exit_code != 0:
		return "Failed to retrieve open ports"

	if output.is_empty():
		return "No open ports found"

	var result := output[0] as String

	if OS.get_name() == "Windows":
		var lines := PackedStringArray()
		for line in result.split("\n"):
			var l := line.strip_edges()
			if l.begins_with("Proto") or l.begins_with("UDP") or "LISTENING" in l:
				lines.append(l)
		if lines.size() <= 1:
			return "No open ports found"
		result = "\n".join(lines)
	GlobalLogger.resultLog("Port scan result: \n" + result)
	return result
