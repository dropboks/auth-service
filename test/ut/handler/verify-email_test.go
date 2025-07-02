package handler_test

import (
	"net/http"
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

type VerifyEmailHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (v *VerifyEmailHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	v.mockAuthService = mockedAuthService
	v.authHandler = handler.New(mockedAuthService, logger)
}

func (v *VerifyEmailHandlerSuite) SetupTest() {
	v.mockAuthService.ExpectedCalls = nil
	v.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestVerifyEmailHandlerSuite(t *testing.T) {
	suite.Run(t, &VerifyEmailHandlerSuite{})
}

func (v *VerifyEmailHandlerSuite) TestAuthHandler_VerifyEmailHandler_Success() {
	userID := "12345"
	token := "verifytoken"
	changeEmailToken := ""

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/verify-email?userid="+userID+"&token="+token, nil)
	ctx.Request = req

	v.mockAuthService.
		On("VerifyEmailService", userID, token, changeEmailToken).
		Return(nil)

	v.authHandler.VerifyEmail(ctx)

	v.Equal(http.StatusOK, w.Code)
	v.Contains(w.Body.String(), "Verification Success")
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *VerifyEmailHandlerSuite) TestAuthHandler_VerifyEmailHandler_MissingInput() {
	token := "verifytoken"

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/verify-email?token="+token, nil)
	ctx.Request = req

	v.authHandler.VerifyEmail(ctx)

	v.Equal(http.StatusBadRequest, w.Code)
	v.Contains(w.Body.String(), "invalid input")
}

func (v *VerifyEmailHandlerSuite) TestAuthHandler_VerifyEmailHandler_InvalidToken() {
	userID := "12345"
	token := "verifytoken"
	changeEmailToken := ""

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/verify-email?userid="+userID+"&token="+token, nil)
	ctx.Request = req

	v.mockAuthService.
		On("VerifyEmailService", userID, token, changeEmailToken).
		Return(dto.Err_UNAUTHORIZED_TOKEN_INVALID)

	v.authHandler.VerifyEmail(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), dto.Err_UNAUTHORIZED_TOKEN_INVALID.Error())
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *VerifyEmailHandlerSuite) TestAuthHandler_VerifyEmailHandler_AlreadyVerfied() {
	userID := "12345"
	token := "verifytoken"
	changeEmailToken := ""

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/verify-email?userid="+userID+"&token="+token, nil)
	ctx.Request = req

	v.mockAuthService.
		On("VerifyEmailService", userID, token, changeEmailToken).
		Return(dto.Err_CONFLICT_USER_ALREADY_VERIFIED)

	v.authHandler.VerifyEmail(ctx)

	v.Equal(http.StatusConflict, w.Code)
	v.Contains(w.Body.String(), dto.Err_CONFLICT_USER_ALREADY_VERIFIED.Error())
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *VerifyEmailHandlerSuite) TestAuthHandler_VerifyEmailHandler_ExpiredVerfied() {
	userID := "12345"
	token := "verifytoken"
	changeEmailToken := ""

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/verify-email?userid="+userID+"&token="+token, nil)
	ctx.Request = req

	v.mockAuthService.
		On("VerifyEmailService", userID, token, changeEmailToken).
		Return(dto.Err_NOTFOUND_KEY_NOTFOUND)

	v.authHandler.VerifyEmail(ctx)

	v.Equal(http.StatusNotFound, w.Code)
	v.Contains(w.Body.String(), "verification token is not found")
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *VerifyEmailHandlerSuite) TestAuthHandler_VerifyEmailHandler_UserNotFound() {
	userID := "12345"
	token := "verifytoken"
	changeEmailToken := ""

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/verify-email?userid="+userID+"&token="+token, nil)
	ctx.Request = req

	v.mockAuthService.
		On("VerifyEmailService", userID, token, changeEmailToken).
		Return(status.Error(codes.NotFound, "user not found"))

	v.authHandler.VerifyEmail(ctx)

	v.Equal(http.StatusNotFound, w.Code)
	v.Contains(w.Body.String(), "user not found")
	v.mockAuthService.AssertExpectations(v.T())
}
