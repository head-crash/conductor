package utils

import (
	"os"
	"strconv"
)

// Include checks if a specific element is present in a slice of strings.
// It returns true if the element is found, otherwise false.
func Include(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// findStringIndex returns the index of the target string in the slice,
// or -1 if the string is not found.
func FindStringIndex(slice []string, target string) int {
	for i, v := range slice {
		if v == target {
			return i
		}
	}
	return -1
}

// GetEnvOrDef returns the value of an environment variable if it exists, otherwise it calls the def () string function.
func GetEnvOrDef(env string, def func() string) string {
	value, exists := os.LookupEnv(env)
	if !exists {
		return def()
	}
	return value
}

func DefaultStringFunc(value string) func() string {
	return func() string { return value }
}

type StrToIntParams struct {
	Value    string
	Fallback string
}

func StringToIntenger(p StrToIntParams) int {
	i, err := strconv.Atoi(p.Value)
	if err != nil {
		return StringToIntenger(StrToIntParams{Value: p.Fallback})
	}
	return i
}
