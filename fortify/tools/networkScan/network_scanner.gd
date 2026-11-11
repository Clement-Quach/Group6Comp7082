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

	return output[0]
