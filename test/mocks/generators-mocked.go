package mocks

import (
	"crypto/rand"

	"github.com/stretchr/testify/mock"
)

type MockRandomGenerator struct {
	mock.Mock
}

func (m *MockRandomGenerator) GenerateUUID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockRandomGenerator) GenerateToken() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockRandomGenerator) GenerateOTP() (string, error) {
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
