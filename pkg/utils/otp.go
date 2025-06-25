package utils

import (
	"crypto/rand"
)

func GenerateOTP() (string, error) {
	const otpLength = 6
	const digits = "0123456789"
	otp := make([]byte, otpLength)
	_, err := rand.Read(otp)
	if err != nil {
		return "", err
	}
	for i := range otpLength {
		otp[i] = digits[otp[i]%10]
	}
	return string(otp), nil
}
