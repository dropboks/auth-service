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
)

type ResendVerificationOTPHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (r *ResendVerificationOTPHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	r.mockAuthService = mockedAuthService
	r.authHandler = handler.New(mockedAuthService, logger)
}

func (r *ResendVerificationOTPHandlerSuite) SetupTest() {
	r.mockAuthService.ExpectedCalls = nil
	r.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestResendVerificationOTPHandlerSuite(t *testing.T) {
	suite.Run(t, &ResendVerificationOTPHandlerSuite{})
}

func (r *ResendVerificationOTPHandlerSuite) TestAuthHandler_ResendVerificationOTPHandler_Success() {
	reqBody := &bytes.Buffer{}

	input := dto.ResendVerificationRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResendVerificationOTPService", input.Email).Return(nil)
	r.authHandler.ResendVerificationOTP(ctx)

	r.Equal(200, w.Code)
	r.Contains(w.Body.String(), "OTP Has been sent to linked email")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *ResendVerificationOTPHandlerSuite) TestAuthHandler_ResendVerificationOTPHandler_MissingInput() {
	reqBody := &bytes.Buffer{}

	encoder := gin.H{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.authHandler.ResendVerificationOTP(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "missing email")
}

func (r *ResendVerificationOTPHandlerSuite) TestAuthHandler_ResendVerificationOTPHandler_UserNotFound() {
	reqBody := &bytes.Buffer{}

	input := dto.ResendVerificationRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResendVerificationOTPService", input.Email).Return(dto.Err_NOTFOUND_USER_NOT_FOUND)
	r.authHandler.ResendVerificationOTP(ctx)

	r.Equal(404, w.Code)
	r.Contains(w.Body.String(), "user not found")
	r.mockAuthService.AssertExpectations(r.T())
}
