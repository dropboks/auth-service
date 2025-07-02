package service_test

import (
	"errors"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	upb "github.com/dropboks/proto-user/pkg/upb"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VerifyEmailServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockJetStreamInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (v *VerifyEmailServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockJetStreamInfra)
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

func (v *VerifyEmailServiceSuite) SetupTest() {
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

func TestVerifyEmailServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyEmailServiceSuite{})
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_SuccessVerifyEmail() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	returnMessageUpdateUser := &upb.Status{Success: true}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(token, nil)
	v.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(returnMessageUpdateUser, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := v.authService.VerifyEmailService(userId, token, "")
	assert.NoError(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_SuccessChangeEmail() {
	userId := "user-id-123"
	changeToken := "valid-change-email-token"
	newEmail := "test2@example.com"
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	returnMessageUpdateUser := &upb.Status{Success: true}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(changeToken, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(newEmail, nil)
	v.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(returnMessageUpdateUser, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := v.authService.VerifyEmailService(userId, "", changeToken)
	assert.NoError(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_AlreadyVerified() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)

	err := v.authService.VerifyEmailService(userId, token, "")
	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_ExpiredToken() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("not-found cause expired"))

	err := v.authService.VerifyEmailService(userId, token, "")

	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_TokenNotMatch() {
	userId := "user-id-123"
	token := "invalid-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("valid-verification-token", nil)

	err := v.authService.VerifyEmailService(userId, token, "")

	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_UserNotFoundWhenUpdating() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(token, nil)
	v.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(nil, status.Error(codes.NotFound, "user-not-found"))

	err := v.authService.VerifyEmailService(userId, token, "")

	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_ExpiredChangeEmailToken() {
	userId := "user-id-123"
	changeToken := "valid-change-email-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("not-found cause expired"))

	err := v.authService.VerifyEmailService(userId, "", changeToken)

	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_ChangeTokenNotMatch() {
	userId := "user-id-123"
	changeToken := "invalid-change-email-verification-token"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("valid-change-email-verification-token", nil)

	err := v.authService.VerifyEmailService(userId, "", changeToken)

	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}
