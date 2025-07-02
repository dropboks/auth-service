package handler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/handler"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type VerifyHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (v *VerifyHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	v.mockAuthService = mockedAuthService
	v.authHandler = handler.New(mockedAuthService, logger)
}

func (v *VerifyHandlerSuite) SetupTest() {
	v.mockAuthService.ExpectedCalls = nil
	v.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestVerifyHandlerSuite(t *testing.T) {
	suite.Run(t, &VerifyHandlerSuite{})
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_Success() {
	token := "Bearer validtoken"
	userID := "12345"

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.mockAuthService.On("VerifyService", "validtoken").Return(userID, nil)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusNoContent, w.Code)
	v.Equal(`{"user_id":"12345"}`, w.Header().Get("User-Data"))
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_MissingToken() {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), "Token is missing")
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_NotFoundKey() {
	token := "Bearer notfoundtoken"
	v.mockAuthService.On("VerifyService", "notfoundtoken").Return("", dto.Err_NOTFOUND_KEY_NOTFOUND)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), dto.Err_NOTFOUND_KEY_NOTFOUND.Error())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_UnauthorizedJWTInvalid() {
	token := "Bearer invalidjwt"
	v.mockAuthService.On("VerifyService", "invalidjwt").Return("", dto.Err_UNAUTHORIZED_JWT_INVALID)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), dto.Err_UNAUTHORIZED_JWT_INVALID.Error())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_InternalGetResource() {
	token := "Bearer internalerror"
	v.mockAuthService.On("VerifyService", "internalerror").Return("", dto.Err_INTERNAL_GET_RESOURCE)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusInternalServerError, w.Code)
	v.Contains(w.Body.String(), "failed to get token")
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_GenericError() {
	token := "Bearer genericerror"
	v.mockAuthService.On("VerifyService", "genericerror").Return("", fmt.Errorf("some error"))

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusInternalServerError, w.Code)
	v.Contains(w.Body.String(), "some error")
}
