package service_test

import (
	"testing"
	"time"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	upb "github.com/dropboks/proto-user/pkg/upb"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LoginServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockJetStreamInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (l *LoginServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockJetStreamInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	l.mockAuthRepo = mockAuthRepo
	l.mockUserClient = mockUserClient
	l.mockFileClient = mockFileClient
	l.mockJetStream = mockJetStream
	l.mockGenerator = mockGenerator
	l.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (l *LoginServiceSuite) SetupTest() {
	l.mockAuthRepo.ExpectedCalls = nil
	l.mockUserClient.ExpectedCalls = nil
	l.mockFileClient.ExpectedCalls = nil
	l.mockJetStream.ExpectedCalls = nil
	l.mockAuthRepo.Calls = nil
	l.mockUserClient.Calls = nil
	l.mockFileClient.Calls = nil
	l.mockJetStream.Calls = nil
}

func TestLoginServiceSuite(t *testing.T) {
	suite.Run(t, &LoginServiceSuite{})
}

func (l *LoginServiceSuite) TestAuthService_LoginService_Success() {

	loginReq := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}

	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == loginReq.Email
	})).Return(mockUser, nil)
	l.mockAuthRepo.On("SetResource", mock.Anything, "session:user-id-123", mock.AnythingOfType("string"), mock.Anything).Return(nil)

	token, err := l.authService.LoginService(loginReq)

	assert.NoError(l.T(), err)
	assert.NotEmpty(l.T(), token)
	l.mockUserClient.AssertExpectations(l.T())
	l.mockAuthRepo.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_UserNotFound() {

	loginReq := dto.LoginRequest{
		Email:    "notfound@example.com",
		Password: "password123",
	}

	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == loginReq.Email
	})).Return(nil, status.Error(codes.NotFound, "user not found"))

	token, err := l.authService.LoginService(loginReq)

	assert.Error(l.T(), err)
	assert.Empty(l.T(), token)
	l.mockUserClient.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_NotVerified() {
	loginReq := dto.LoginRequest{
		Email:    "notverified@example.com",
		Password: "password123",
	}

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "notverified@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == loginReq.Email
	})).Return(mockUser, nil)

	token, err := l.authService.LoginService(loginReq)

	assert.Error(l.T(), err)
	assert.Empty(l.T(), token)
	l.mockUserClient.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_WrongPassword() {
	loginReq := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == loginReq.Email
	})).Return(mockUser, nil)

	token, err := l.authService.LoginService(loginReq)

	assert.Error(l.T(), err)
	assert.Empty(l.T(), token)
	l.mockUserClient.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_WithTwoFactor() {
	loginReq := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	mockPubAck := &jetstream.PubAck{
		Stream:   "test-stream",
		Sequence: 1,
	}

	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == loginReq.Email
	})).Return(mockUser, nil)
	l.mockGenerator.On("GenerateOTP").Return("123456", nil)

	l.mockAuthRepo.On("SetResource", mock.Anything, "OTP:user-id-123", mock.AnythingOfType("string"), mock.Anything).Return(nil)
	l.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)

	token, err := l.authService.LoginService(loginReq)

	assert.NoError(l.T(), err)
	assert.Empty(l.T(), token)
	l.mockUserClient.AssertExpectations(l.T())
	l.mockAuthRepo.AssertExpectations(l.T())

	time.Sleep(100 * time.Millisecond)
	l.mockJetStream.AssertExpectations(l.T())
}
