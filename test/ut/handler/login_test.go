package handler_test

import (
	"bytes"
	"encoding/json"
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

type LoginHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (l *LoginHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	l.mockAuthService = mockedAuthService
	l.authHandler = handler.New(mockedAuthService, logger)
}

func (l *LoginHandlerSuite) SetupTest() {
	l.mockAuthService.ExpectedCalls = nil
	l.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestLoginHandlerSuite(t *testing.T) {
	suite.Run(t, &LoginHandlerSuite{})
}

func (l *LoginHandlerSuite) TestAuthHandler_LoginHandler_Success() {
	reqBody := &bytes.Buffer{}

	input := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	encoder := gin.H{
		"email":    "test@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/v1/login", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("LoginService", input).Return("mocked-token", nil)
	l.authHandler.Login(ctx)

	l.Equal(200, w.Code)
	l.Contains(w.Body.String(), "mocked-token")
	l.mockAuthService.AssertExpectations(l.T())
}
func (l *LoginHandlerSuite) TestAuthHandler_LoginHandler_Success2FA() {
	reqBody := &bytes.Buffer{}

	input := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	encoder := gin.H{
		"email":    "test@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/v1/login", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("LoginService", input).Return("", nil)
	l.authHandler.Login(ctx)

	l.Equal(200, w.Code)
	l.Contains(w.Body.String(), "OTP Has been sent to linked email")
	l.mockAuthService.AssertExpectations(l.T())
}

func (l *LoginHandlerSuite) TestAuthHandler_LoginHandler_MissingInput() {
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)
	request := httptest.NewRequest("POST", "/v1/login", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.authHandler.Login(ctx)

	l.Equal(400, w.Code)
	l.Contains(w.Body.String(), "invalid input")
}

func (l *LoginHandlerSuite) TestAuthHandler_LoginHandler_WrongPassword() {
	reqBody := &bytes.Buffer{}

	input := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	encoder := gin.H{
		"email":    "test@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)
	request := httptest.NewRequest("POST", "/v1/login", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("LoginService", input).Return("", dto.Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH)
	l.authHandler.Login(ctx)

	l.Equal(401, w.Code)
	l.Contains(w.Body.String(), "email or password is wrong")
}

func (l *LoginHandlerSuite) TestAuthHandler_LoginHandler_NotVerified() {
	reqBody := &bytes.Buffer{}

	input := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	encoder := gin.H{
		"email":    "test@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)
	request := httptest.NewRequest("POST", "/v1/login", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("LoginService", input).Return("", dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED)
	l.authHandler.Login(ctx)

	l.Equal(401, w.Code)
	l.Contains(w.Body.String(), "user is not verified")
}

func (l *LoginHandlerSuite) TestAuthHandler_LoginHandler_NotFound() {
	reqBody := &bytes.Buffer{}

	input := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	encoder := gin.H{
		"email":    "test@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)
	request := httptest.NewRequest("POST", "/v1/login", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("LoginService", input).Return("", status.Error(codes.NotFound, "user not found"))
	l.authHandler.Login(ctx)

	l.Equal(404, w.Code)
	l.Contains(w.Body.String(), "user not found")
}
