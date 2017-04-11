package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

func generateSecret(len int) (string, error) {
	data := make([]byte, len)
	n, err := rand.Read(data)
	if err != nil {
		return "", err
	}
	if n != len {
		return "", errors.New("Config: RNG failed")
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func arrayContains(arr []string, line string) bool {
	for _, l := range arr {
		if l == line {
			return true
		}
	}
	return false
}
