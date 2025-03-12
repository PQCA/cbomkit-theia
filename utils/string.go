package utils

import "strings"

func StandardizeString(in string) string {
	replacer := strings.NewReplacer("-", "", "_", "", " ", "", "/", "")
	replaced := replacer.Replace(in)
	return strings.ToUpper(extractPrefix(replaced))
}

func extractPrefix(s string) string {
	for i, char := range s {
		if char >= '0' && char <= '9' {
			return s[:i]
		}
	}
	return s
}
