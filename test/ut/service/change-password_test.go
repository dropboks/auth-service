package service_test

import (
	"errors"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
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

type ChangePasswordServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (c *ChangePasswordServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	// logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	c.mockAuthRepo = mockAuthRepo
	c.mockUserClient = mockUserClient
	c.mockFileClient = mockFileClient
	c.mockJetStream = mockJetStream
	c.mockGenerator = mockGenerator
	c.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (c *ChangePasswordServiceSuite) SetupTest() {
	c.mockAuthRepo.ExpectedCalls = nil
	c.mockUserClient.ExpectedCalls = nil
	c.mockFileClient.ExpectedCalls = nil
	c.mockJetStream.ExpectedCalls = nil
	c.mockGenerator.ExpectedCalls = nil
	c.mockAuthRepo.Calls = nil
	c.mockUserClient.Calls = nil
	c.mockFileClient.Calls = nil
	c.mockJetStream.Calls = nil
	c.mockGenerator.Calls = nil
}

func TestChangePasswordServiceSuite(t *testing.T) {
	suite.Run(t, &ChangePasswordServiceSuite{})
}
func (c *ChangePasswordServiceSuite) TestAuthService_ChangePasswordService_Success() {
	userid := "user-id-123"
	resetPasswordToken := "reset-password-token"
	req := &dto.ChangePasswordRequest{
		Password:        "new-password",
		ConfirmPassword: "new-password",
	}
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}
	returnMessageUpdateUser := &upb.Status{Success: true}

	c.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(resetPasswordToken, nil)
	c.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	c.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(returnMessageUpdateUser, nil)
	c.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := c.authService.ChangePasswordService(userid, resetPasswordToken, req)

	assert.NoError(c.T(), err)
	c.mockAuthRepo.AssertExpectations(c.T())
	c.mockUserClient.AssertExpectations(c.T())
}

func (c *ChangePasswordServiceSuite) TestAuthService_ChangePasswordService_ExpiredToken() {
	userid := "user-id-123"
	resetPasswordToken := "reset-password-token"
	req := &dto.ChangePasswordRequest{
		Password:        "new-password",
		ConfirmPassword: "new-password",
	}
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}
	c.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	c.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("token not found"))

	err := c.authService.ChangePasswordService(userid, resetPasswordToken, req)

	assert.Error(c.T(), err)
	c.mockAuthRepo.AssertExpectations(c.T())
	c.mockUserClient.AssertExpectations(c.T())
}

func (c *ChangePasswordServiceSuite) TestAuthService_ChangePasswordService_InvalidToken() {
	userid := "user-id-123"
	resetPasswordToken := "invalid-reset-password-token"
	req := &dto.ChangePasswordRequest{
		Password:        "new-password",
		ConfirmPassword: "new-password",
	}
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}
	c.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)

	c.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("valid-reset-password-token", nil)

	err := c.authService.ChangePasswordService(userid, resetPasswordToken, req)

	assert.Error(c.T(), err)
	c.mockAuthRepo.AssertExpectations(c.T())
}

func (c *ChangePasswordServiceSuite) TestAuthService_ChangePasswordService_PasswordAndConfirmPasswordNotMatch() {
	userid := "user-id-123"
	resetPasswordToken := "reset-password-token"
	req := &dto.ChangePasswordRequest{
		Password:        "new-password",
		ConfirmPassword: "different-new-password",
	}

	err := c.authService.ChangePasswordService(userid, resetPasswordToken, req)

	assert.Error(c.T(), err)
}

func (c *ChangePasswordServiceSuite) TestAuthService_ChangePasswordService_UserNotFound() {
	userid := "user-id-123"
	resetPasswordToken := "reset-password-token"
	req := &dto.ChangePasswordRequest{
		Password:        "new-password",
		ConfirmPassword: "new-password",
	}

	c.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("user not found"))

	err := c.authService.ChangePasswordService(userid, resetPasswordToken, req)

	assert.Error(c.T(), err)
	c.mockUserClient.AssertExpectations(c.T())
}

func (c *ChangePasswordServiceSuite) TestAuthService_ChangePasswordService_UserNotFoundWhenUpdating() {
	userid := "user-id-123"
	resetPasswordToken := "reset-password-token"
	req := &dto.ChangePasswordRequest{
		Password:        "new-password",
		ConfirmPassword: "new-password",
	}
	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	c.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(resetPasswordToken, nil)
	c.mockUserClient.On("GetUserByUserId", mock.Anything, mock.Anything, mock.Anything).Return(mockUser, nil)
	c.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(nil, status.Error(codes.NotFound, "user not found"))

	err := c.authService.ChangePasswordService(userid, resetPasswordToken, req)

	assert.Error(c.T(), err)
	c.mockAuthRepo.AssertExpectations(c.T())
	c.mockUserClient.AssertExpectations(c.T())
}
