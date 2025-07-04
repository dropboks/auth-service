package service_test

import (
	"testing"

	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type LogoutServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockJetStreamInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (l *LogoutServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockJetStreamInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	// logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	l.mockAuthRepo = mockAuthRepo
	l.mockUserClient = mockUserClient
	l.mockFileClient = mockFileClient
	l.mockJetStream = mockJetStream
	l.mockGenerator = mockGenerator
	l.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (l *LogoutServiceSuite) SetupTest() {
	l.mockAuthRepo.ExpectedCalls = nil
	l.mockUserClient.ExpectedCalls = nil
	l.mockFileClient.ExpectedCalls = nil
	l.mockJetStream.ExpectedCalls = nil
	l.mockGenerator.ExpectedCalls = nil
	l.mockAuthRepo.Calls = nil
	l.mockUserClient.Calls = nil
	l.mockFileClient.Calls = nil
	l.mockJetStream.Calls = nil
	l.mockGenerator.Calls = nil
}

func TestLogoutServiceSuite(t *testing.T) {
	suite.Run(t, &LogoutServiceSuite{})
}

func (l *LogoutServiceSuite) TestAuthService_LogoutService_Success() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"

	l.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := l.authService.LogoutService(jwt)

	assert.NoError(l.T(), err)

	l.mockAuthRepo.AssertExpectations(l.T())
}
func (l *LogoutServiceSuite) TestAuthService_LogoutService_TokenInvalid() {
	jwt := "access-token"

	err := l.authService.LogoutService(jwt)

	assert.Error(l.T(), err)
}
