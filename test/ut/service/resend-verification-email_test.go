package service_test

import (
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/dropboks/sharedlib/model"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ResendVerificationEmailServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (r *ResendVerificationEmailServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	r.mockAuthRepo = mockAuthRepo
	r.mockUserClient = mockUserClient
	r.mockJetStream = mockJetStream
	r.mockGenerator = mockGenerator
	r.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (r *ResendVerificationEmailServiceSuite) SetupTest() {
	r.mockAuthRepo.ExpectedCalls = nil
	r.mockUserClient.ExpectedCalls = nil
	r.mockJetStream.ExpectedCalls = nil
	r.mockGenerator.ExpectedCalls = nil
	r.mockAuthRepo.Calls = nil
	r.mockUserClient.Calls = nil
	r.mockJetStream.Calls = nil
	r.mockGenerator.Calls = nil
}

func TestResendVerificationEmailServiceSuite(t *testing.T) {
	suite.Run(t, &ResendVerificationEmailServiceSuite{})
}
func (r *ResendVerificationEmailServiceSuite) TestAuthService_ResendVerificationEmailService_Success() {
	email := "test@example.com"
	verificationToken := "generated-verification-token"
	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	mockPubAck := &jetstream.PubAck{
		Stream:   "test-stream",
		Sequence: 1,
	}

	r.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	r.mockGenerator.On("GenerateToken").Return(verificationToken, nil)
	r.mockAuthRepo.On("SetResource", mock.Anything, "verificationToken:user-id-123", verificationToken, mock.Anything).Return(nil)
	r.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)

	err := r.authService.ResendVerificationService(email)

	r.NoError(err)

	r.mockUserClient.AssertExpectations(r.T())
	r.mockGenerator.AssertExpectations(r.T())
	r.mockAuthRepo.AssertExpectations(r.T())
	r.mockJetStream.AssertExpectations(r.T())
}

func (r *ResendVerificationEmailServiceSuite) TestAuthService_ResendVerificationEmailService_UserNotFound() {
	email := "test@example.com"
	r.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(nil, dto.Err_NOTFOUND_USER_NOT_FOUND)

	err := r.authService.ResendVerificationService(email)

	r.Error(err)
	r.mockAuthRepo.AssertExpectations(r.T())
}

func (r *ResendVerificationEmailServiceSuite) TestAuthService_ResendVerificationEmailService_AlreadyVerified() {
	email := "test@example.com"
	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}
	r.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	err := r.authService.ResendVerificationService(email)

	r.Error(err)
	r.mockAuthRepo.AssertExpectations(r.T())
}
