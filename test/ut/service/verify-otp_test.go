package service_test

import (
	"errors"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/dropboks/sharedlib/model"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerifyOTPServiceSuite struct {
	suite.Suite
	authService  service.AuthService
	mockAuthRepo *mocks.MockAuthRepository
}

func (v *VerifyOTPServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	v.mockAuthRepo = mockAuthRepo
	v.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (v *VerifyOTPServiceSuite) SetupTest() {
	v.mockAuthRepo.ExpectedCalls = nil

	v.mockAuthRepo.Calls = nil
}

func TestVerifyOTPServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyOTPServiceSuite{})
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_Success() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(otp, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	v.mockAuthRepo.On("SetResource", mock.Anything, mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	token, err := v.authService.VerifyOTPService(otp, email)
	v.NotEmpty(token)
	v.NoError(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_UserNotFound() {
	otp := "123456"
	email := "test@example.com"

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(nil, dto.Err_NOTFOUND_USER_NOT_FOUND)

	token, err := v.authService.VerifyOTPService(otp, email)
	v.Empty(token)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_ExpiredOTP() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("token-not-found"))

	token, err := v.authService.VerifyOTPService(otp, email)

	v.Empty(token)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_InvalidOTP() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("654321", nil)

	token, err := v.authService.VerifyOTPService(otp, email)
	v.Empty(token)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}
