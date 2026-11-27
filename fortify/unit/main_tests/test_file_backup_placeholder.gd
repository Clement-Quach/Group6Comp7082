extends GutTest

const PlaceholderBackupScript = preload("res://tools/fileBackup/fileBackup.gd")


# fileBackup.gd currently has only an empty Node lifecycle. This checks that
# the placeholder script still loads; it has no business logic to unit-test.
func test_placeholder_script_can_be_instantiated() -> void:
	var placeholder: Node = PlaceholderBackupScript.new()
	assert_true(placeholder is Node)
	placeholder.free()
