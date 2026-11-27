extends GutTest

var _scanner: NetworkScanner


func before_each() -> void:
	_scanner = NetworkScanner.new()
	add_child(_scanner)


func after_each() -> void:
	_scanner.free()


# NetworkScanner calls OS.execute() directly, so it has no deterministic unit
# seam. These smoke tests run the project's read-only arp/netstat/ss commands.
func test_arp_scan_returns_output_or_a_handled_status_message() -> void:
	var result := _scanner.get_arp_table()
	assert_true(result is String)
	assert_false(result.strip_edges().is_empty())


func test_port_scan_returns_output_or_a_handled_status_message() -> void:
	var result := _scanner.get_open_ports()
	assert_true(result is String)
	assert_false(result.strip_edges().is_empty())
