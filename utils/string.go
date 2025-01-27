package utils

import "strings"

func StandardizeString(in string) string {
	replacer := strings.NewReplacer("-", "", "_", "", " ", "", "/", "")
	return replacer.Replace(in)
}
