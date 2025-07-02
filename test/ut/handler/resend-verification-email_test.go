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

type ResendVerificationEmailHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (r *ResendVerificationEmailHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	r.mockAuthService = mockedAuthService
	r.authHandler = handler.New(mockedAuthService, logger)
}

func (r *ResendVerificationEmailHandlerSuite) SetupTest() {
	r.mockAuthService.ExpectedCalls = nil
	r.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestResendVerificationEmailHandlerSuite(t *testing.T) {
	suite.Run(t, &ResendVerificationEmailHandlerSuite{})
}

func (r *ResendVerificationEmailHandlerSuite) TestAuthHandler_ResendVerificationEmailHandler_Success() {
	reqBody := &bytes.Buffer{}

	input := dto.ResendVerificationRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-email", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResendVerificationService", input.Email).Return(nil)
	r.authHandler.ResendVerficationEmail(ctx)

	r.Equal(200, w.Code)
	r.Contains(w.Body.String(), "Check your email for verification")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *ResendVerificationEmailHandlerSuite) TestAuthHandler_ResendVerificationEmailHandler_MissingEmail() {
	reqBody := &bytes.Buffer{}

	encoder := gin.H{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-email", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.authHandler.ResendVerficationEmail(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "missing email")
}

func (r *ResendVerificationEmailHandlerSuite) TestAuthHandler_ResendVerificationEmailHandler_AlreadyVerified() {
	reqBody := &bytes.Buffer{}

	input := dto.ResendVerificationRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-email", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResendVerificationService", input.Email).Return(dto.Err_CONFLICT_USER_ALREADY_VERIFIED)
	r.authHandler.ResendVerficationEmail(ctx)

	r.Equal(409, w.Code)
	r.Contains(w.Body.String(), dto.Err_CONFLICT_USER_ALREADY_VERIFIED.Error())
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *ResendVerificationEmailHandlerSuite) TestAuthHandler_ResendVerificationEmailHandler_UserNotFound() {
	reqBody := &bytes.Buffer{}

	input := dto.ResendVerificationRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/resend-verification-email", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResendVerificationService", input.Email).Return(status.Error(codes.NotFound, "user not found"))
	r.authHandler.ResendVerficationEmail(ctx)

	r.Equal(404, w.Code)
	r.Contains(w.Body.String(), "user not found")
	r.mockAuthService.AssertExpectations(r.T())
}
