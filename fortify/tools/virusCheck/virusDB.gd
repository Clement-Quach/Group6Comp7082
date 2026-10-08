extends Node
class_name virusDB

var database = ["example string"]

func checkDB(hash: String) -> bool:
	for item in database:
		if hash == item:
			print("found in DB")
			return true

	print("not found in DB")
	return false
