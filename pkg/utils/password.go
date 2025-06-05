package utils

import "golang.org/x/crypto/bcrypt"

func HashPasswordCompare(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 17)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}
