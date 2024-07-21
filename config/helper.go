package config

import (
	"log"
	"strconv"
)

type strToIntParams struct {
	value    string
	fallback string
}

func StringToIntenger(p strToIntParams) int {
	i, err := strconv.Atoi(p.value)
	if err != nil {
		log.Printf("Failed to convert string to int: %s", p.value)
		if p.fallback == "" {
			log.Fatal("Critical error: No default string value has been defined!")
		}
		return StringToIntenger(strToIntParams{value: p.fallback})
	}
	return i
}

func strToInt(v string) int {
	return StringToIntenger(strToIntParams{value: v})
}
