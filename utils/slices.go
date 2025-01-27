package utils

// RemoveFromSlice Remove a single item by index s from a slice
func RemoveFromSlice[T interface{}](slice []T, s int) []T {
	return append(slice[:s], slice[s+1:]...)
}
