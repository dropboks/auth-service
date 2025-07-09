package service_test

import (
	"testing"
	"time"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/dropboks/sharedlib/model"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LoginServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (l *LoginServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	l.mockAuthRepo = mockAuthRepo
	l.mockFileClient = mockFileClient
	l.mockJetStream = mockJetStream
	l.mockGenerator = mockGenerator
	l.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (l *LoginServiceSuite) SetupTest() {
	l.mockAuthRepo.ExpectedCalls = nil
	l.mockFileClient.ExpectedCalls = nil
	l.mockJetStream.ExpectedCalls = nil
	l.mockAuthRepo.Calls = nil
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

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}

	l.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	l.mockAuthRepo.On("SetResource", mock.Anything, mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	token, err := l.authService.LoginService(loginReq)

	l.NoError(err)
	l.NotEmpty(token)
	l.mockAuthRepo.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_UserNotFound() {

	loginReq := dto.LoginRequest{
		Email:    "notfound@example.com",
		Password: "password123",
	}

	l.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(nil, status.Error(codes.NotFound, "user not found"))

	token, err := l.authService.LoginService(loginReq)

	l.Error(err)
	l.Empty(token)
	l.mockAuthRepo.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_NotVerified() {
	loginReq := dto.LoginRequest{
		Email:    "notverified@example.com",
		Password: "password123",
	}

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "notverified@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	l.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)

	token, err := l.authService.LoginService(loginReq)

	l.Error(err)
	l.Empty(token)
	l.mockAuthRepo.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_WrongPassword() {
	loginReq := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	l.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)

	token, err := l.authService.LoginService(loginReq)

	l.Error(err)
	l.Empty(token)
	l.mockAuthRepo.AssertExpectations(l.T())
}

func (l *LoginServiceSuite) TestAuthService_LoginService_WithTwoFactor() {
	loginReq := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	mockPubAck := &jetstream.PubAck{
		Stream:   "test-stream",
		Sequence: 1,
	}

	l.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	l.mockGenerator.On("GenerateOTP").Return("123456", nil)

	l.mockAuthRepo.On("SetResource", mock.Anything, "OTP:user-id-123", mock.AnythingOfType("string"), mock.Anything).Return(nil)
	l.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)

	token, err := l.authService.LoginService(loginReq)

	l.NoError(err)
	l.Empty(token)
	l.mockAuthRepo.AssertExpectations(l.T())
	l.mockAuthRepo.AssertExpectations(l.T())

	time.Sleep(100 * time.Millisecond)
	l.mockJetStream.AssertExpectations(l.T())
}
