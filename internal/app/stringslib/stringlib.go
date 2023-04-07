package stringslib

// StringInSlice returns true if the given slice contains the given string
func StringInSlice(s string, data []string) bool {
	for _, st := range data {
		if s == st {
			return true
		}
	}
	return false
}
