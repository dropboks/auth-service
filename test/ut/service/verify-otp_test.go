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
)

type VerifyOTPServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (v *VerifyOTPServiceSuite) SetupSuite() {

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

func (v *VerifyOTPServiceSuite) SetupTest() {
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

func TestVerifyOTPServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyOTPServiceSuite{})
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_Success() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(otp, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	v.mockAuthRepo.On("SetResource", mock.Anything, "session:user-id-123", mock.AnythingOfType("string"), mock.Anything).Return(nil)

	token, err := v.authService.VerifyOTPService(otp, email)

	assert.NotEmpty(v.T(), token)
	assert.NoError(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_UserNotFound() {
	otp := "123456"
	email := "test@example.com"

	v.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("not-found"))

	token, err := v.authService.VerifyOTPService(otp, email)

	assert.Empty(v.T(), token)
	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_ExpiredOTP() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("token-not-found"))

	token, err := v.authService.VerifyOTPService(otp, email)

	assert.Empty(v.T(), token)
	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_InvalidOTP() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockUserClient.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("654321", nil)

	token, err := v.authService.VerifyOTPService(otp, email)

	assert.Empty(v.T(), token)
	assert.Error(v.T(), err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}
