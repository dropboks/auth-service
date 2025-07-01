package mocks

import (
	"github.com/dropboks/auth-service/internal/domain/dto"
	m "github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	m.Mock
}

func (m *MockAuthService) LoginService(req dto.LoginRequest) (string, error) {
	args := m.Called(req)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) RegisterService(req dto.RegisterRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *MockAuthService) VerifyService(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) LogoutService(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockAuthService) VerifyEmailService(userId, token, changeToken string) error {
	args := m.Called(userId, token, changeToken)
	return args.Error(0)
}

func (m *MockAuthService) ResendVerificationService(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockAuthService) VerifyOTPService(otp, email string) (string, error) {
	args := m.Called(otp, email)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ResendVerificationOTPService(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockAuthService) ResetPasswordService(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockAuthService) ChangePasswordService(userId, resetPasswordToken string, req *dto.ChangePasswordRequest) error {
	args := m.Called(userId, resetPasswordToken, req)
	return args.Error(0)
}
