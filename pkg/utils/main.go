package utils

func BoolToUint8(value bool) uint8 {
	var converted uint8
	if value {
		converted = 1
	}

	return converted
}
