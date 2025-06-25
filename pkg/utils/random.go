package utils

import (
	"crypto/rand"
	"encoding/hex"
)

func RandomString64() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
