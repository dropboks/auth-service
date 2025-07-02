package mocks

import (
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
	args := m.Called()
	return args.String(0), args.Error(1)
}
