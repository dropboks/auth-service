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

type ResetPasswordServiceSuite struct {
	suite.Suite
	authService   service.AuthService
	mockAuthRepo  *mocks.MockAuthRepository
	mockJetStream *mocks.MockNatsInfra
	mockGenerator *mocks.MockRandomGenerator
}

func (r *ResetPasswordServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	r.mockAuthRepo = mockAuthRepo
	r.mockJetStream = mockJetStream
	r.mockGenerator = mockGenerator
	r.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (r *ResetPasswordServiceSuite) SetupTest() {
	r.mockAuthRepo.ExpectedCalls = nil
	r.mockJetStream.ExpectedCalls = nil
	r.mockGenerator.ExpectedCalls = nil
	r.mockAuthRepo.Calls = nil
	r.mockJetStream.Calls = nil
	r.mockGenerator.Calls = nil
}

func TestResetPasswordServiceSuite(t *testing.T) {
	suite.Run(t, &ResetPasswordServiceSuite{})
}
func (r *ResetPasswordServiceSuite) TestAuthService_ResetPasswordService_Success() {
	email := "test@example.com"
	mockPubAck := &jetstream.PubAck{
		Stream:   "test-stream",
		Sequence: 1,
	}

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	r.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	r.mockGenerator.On("GenerateToken", mock.Anything).Return("token-generated", nil)
	r.mockAuthRepo.On("SetResource", mock.Anything, "resetPasswordToken:user-id-123", mock.AnythingOfType("string"), mock.Anything).Return(nil)
	r.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)

	err := r.authService.ResetPasswordService(email)

	r.NoError(err)
	r.mockGenerator.AssertExpectations(r.T())
	r.mockAuthRepo.AssertExpectations(r.T())
	r.mockJetStream.AssertExpectations(r.T())

}

func (r *ResetPasswordServiceSuite) TestAuthService_ResetPasswordService_UserNotFOund() {
	email := "test@example.com"

	r.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(nil, dto.Err_NOTFOUND_USER_NOT_FOUND)

	err := r.authService.ResetPasswordService(email)
	r.Error(err)
	r.mockAuthRepo.AssertExpectations(r.T())

}
