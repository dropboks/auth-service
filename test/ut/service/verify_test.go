package service_test

import (
	"errors"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerifyServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (v *VerifyServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	// logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	v.mockAuthRepo = mockAuthRepo
	v.mockUserClient = mockUserClient
	v.mockFileClient = mockFileClient
	v.mockJetStream = mockJetStream
	v.mockGenerator = mockGenerator
	v.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (v *VerifyServiceSuite) SetupTest() {
	v.mockAuthRepo.ExpectedCalls = nil
	v.mockUserClient.ExpectedCalls = nil
	v.mockFileClient.ExpectedCalls = nil
	v.mockJetStream.ExpectedCalls = nil
	v.mockGenerator.ExpectedCalls = nil
	v.mockAuthRepo.Calls = nil
	v.mockUserClient.Calls = nil
	v.mockFileClient.Calls = nil
	v.mockJetStream.Calls = nil
	v.mockGenerator.Calls = nil
}

func TestVerifyServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyServiceSuite{})
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_Success() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI", nil)

	userId, err := v.authService.VerifyService(jwt)

	assert.Equal(v.T(), userId, "user-id-123")
	assert.NoError(v.T(), err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_NotValidOrExpire() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJleHAiOjE3NTEzNjIwODgsImlhdCI6MTc1MTM2MjA4OH0.quJxCGSx9yQEhdHaZDFEQ7x_shNjb-nuE5FMqtuVKvA"

	_, err := v.authService.VerifyService(jwt)

	assert.Error(v.T(), err)

}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_DifferentWithState() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"
	returnedJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjE5OTN9.hutDnLuLsqZSEtOmytC-x25Fria5ycPjd_4XC47C2uM"
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(returnedJwt, nil)

	_, err := v.authService.VerifyService(jwt)

	assert.Error(v.T(), err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_NotFound() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("notfound"))

	_, err := v.authService.VerifyService(jwt)

	assert.Error(v.T(), err)

	v.mockAuthRepo.AssertExpectations(v.T())
}
