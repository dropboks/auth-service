package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/handler"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ChangePasswordHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (c *ChangePasswordHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	c.mockAuthService = mockedAuthService
	c.authHandler = handler.New(mockedAuthService, logger)
}

func (c *ChangePasswordHandlerSuite) SetupTest() {
	c.mockAuthService.ExpectedCalls = nil
	c.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestChangePasswordHandlerSuite(t *testing.T) {
	suite.Run(t, &ChangePasswordHandlerSuite{})
}

func (c *ChangePasswordHandlerSuite) TestAuthHandler_ChangePasswordHandler_Success() {

	userId := "userid-123"
	resetPasswordToken := "reset-password-token"
	input := dto.ChangePasswordRequest{
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	encoder := gin.H{
		"password":         "password123",
		"confirm_password": "password123",
	}
	reqBody := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", fmt.Sprintf("/change-password?userid=%s&resetPasswordToken=%s", userId, resetPasswordToken), reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	c.mockAuthService.On("ChangePasswordService", userId, resetPasswordToken, &input).Return(nil)
	c.authHandler.ChangePassword(ctx)

	c.Equal(200, w.Code)
	c.Contains(w.Body.String(), "password changed")
	c.mockAuthService.AssertExpectations(c.T())
}

func (c *ChangePasswordHandlerSuite) TestAuthHandler_ChangePasswordHandler_MissingQuery() {

	encoder := gin.H{
		"password":         "password123",
		"confirm_password": "password123",
	}
	reqBody := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/change-password", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	c.authHandler.ChangePassword(ctx)

	c.Equal(400, w.Code)
	c.Contains(w.Body.String(), "invalid input")
}

func (c *ChangePasswordHandlerSuite) TestAuthHandler_ChangePasswordHandler_MissingBody() {

	userId := "userid-123"
	resetPasswordToken := "reset-password-token"

	encoder := gin.H{}
	reqBody := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", fmt.Sprintf("/change-password?userid=%s&resetPasswordToken=%s", userId, resetPasswordToken), reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	c.authHandler.ChangePassword(ctx)

	c.Equal(400, w.Code)
	c.Contains(w.Body.String(), "invalid input")
}

func (c *ChangePasswordHandlerSuite) TestAuthHandler_ChangePasswordHandler_InvalidToken() {

	userId := "userid-123"
	resetPasswordToken := "reset-password-token"
	input := dto.ChangePasswordRequest{
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	encoder := gin.H{
		"password":         "password123",
		"confirm_password": "password123",
	}
	reqBody := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", fmt.Sprintf("/change-password?userid=%s&resetPasswordToken=%s", userId, resetPasswordToken), reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	c.mockAuthService.On("ChangePasswordService", userId, resetPasswordToken, &input).Return(dto.Err_UNAUTHORIZED_TOKEN_INVALID)
	c.authHandler.ChangePassword(ctx)

	c.Equal(401, w.Code)
	c.Contains(w.Body.String(), "invalid token")
	c.mockAuthService.AssertExpectations(c.T())
}

func (c *ChangePasswordHandlerSuite) TestAuthHandler_ChangePasswordHandler_PasswordAndConfirmPasswordNotMatch() {

	userId := "userid-123"
	resetPasswordToken := "reset-password-token"
	input := dto.ChangePasswordRequest{
		Password:        "password123",
		ConfirmPassword: "password1234",
	}

	encoder := gin.H{
		"password":         "password123",
		"confirm_password": "password1234",
	}
	reqBody := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", fmt.Sprintf("/change-password?userid=%s&resetPasswordToken=%s", userId, resetPasswordToken), reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	c.mockAuthService.On("ChangePasswordService", userId, resetPasswordToken, &input).Return(dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH)
	c.authHandler.ChangePassword(ctx)

	c.Equal(400, w.Code)
	c.Contains(w.Body.String(), dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH.Error())
	c.mockAuthService.AssertExpectations(c.T())
}

func (c *ChangePasswordHandlerSuite) TestAuthHandler_ChangePasswordHandler_UserNotFound() {

	userId := "userid-123"
	resetPasswordToken := "reset-password-token"
	input := dto.ChangePasswordRequest{
		Password:        "password123",
		ConfirmPassword: "password1234",
	}

	encoder := gin.H{
		"password":         "password123",
		"confirm_password": "password1234",
	}
	reqBody := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", fmt.Sprintf("/change-password?userid=%s&resetPasswordToken=%s", userId, resetPasswordToken), reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	c.mockAuthService.On("ChangePasswordService", userId, resetPasswordToken, &input).Return(status.Error(codes.NotFound, "user not found"))
	c.authHandler.ChangePassword(ctx)

	c.Equal(404, w.Code)
	c.Contains(w.Body.String(), "user not found")
	c.mockAuthService.AssertExpectations(c.T())
}
