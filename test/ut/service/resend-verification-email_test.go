package service_test

import (
	"errors"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	upb "github.com/dropboks/proto-user/pkg/upb"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ResendVerificationEmailServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockJetStreamInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (r *ResendVerificationEmailServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockJetStreamInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	// logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	r.mockAuthRepo = mockAuthRepo
	r.mockUserClient = mockUserClient
	r.mockFileClient = mockFileClient
	r.mockJetStream = mockJetStream
	r.mockGenerator = mockGenerator
	r.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (r *ResendVerificationEmailServiceSuite) SetupTest() {
	r.mockAuthRepo.ExpectedCalls = nil
	r.mockUserClient.ExpectedCalls = nil
	r.mockFileClient.ExpectedCalls = nil
	r.mockJetStream.ExpectedCalls = nil
	r.mockGenerator.ExpectedCalls = nil
	r.mockAuthRepo.Calls = nil
	r.mockUserClient.Calls = nil
	r.mockFileClient.Calls = nil
	r.mockJetStream.Calls = nil
	r.mockGenerator.Calls = nil
}

func TestResendVerificationEmailServiceSuite(t *testing.T) {
	suite.Run(t, &ResendVerificationEmailServiceSuite{})
}
func (r *ResendVerificationEmailServiceSuite) TestAuthService_ResendVerificationEmailService_Success() {
	email := "test@example.com"
	verificationToken := "generated-verification-token"
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	mockPubAck := &jetstream.PubAck{
		Stream:   "test-stream",
		Sequence: 1,
	}

	r.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	r.mockGenerator.On("GenerateToken").Return(verificationToken, nil)
	r.mockAuthRepo.On("SetResource", mock.Anything, "verificationToken:user-id-123", verificationToken, mock.Anything).Return(nil)
	r.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)
	err := r.authService.ResendVerificationService(email)

	assert.NoError(r.T(), err)
	r.mockUserClient.AssertExpectations(r.T())
	r.mockGenerator.AssertExpectations(r.T())
	r.mockAuthRepo.AssertExpectations(r.T())
	r.mockJetStream.AssertExpectations(r.T())
}

func (r *ResendVerificationEmailServiceSuite) TestAuthService_ResendVerificationEmailService_UserNotFound() {
	email := "test@example.com"
	r.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("user not foun"))
	err := r.authService.ResendVerificationService(email)

	assert.Error(r.T(), err)
	r.mockUserClient.AssertExpectations(r.T())
}

func (r *ResendVerificationEmailServiceSuite) TestAuthService_ResendVerificationEmailService_AlreadyVerified() {
	email := "test@example.com"
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}
	r.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	err := r.authService.ResendVerificationService(email)

	assert.Error(r.T(), err)
	r.mockUserClient.AssertExpectations(r.T())
}
