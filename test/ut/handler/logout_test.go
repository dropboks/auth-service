package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/handler"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type LogoutHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (v *LogoutHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	v.mockAuthService = mockedAuthService
	v.authHandler = handler.New(mockedAuthService, logger)
}

func (v *LogoutHandlerSuite) SetupTest() {
	v.mockAuthService.ExpectedCalls = nil
	v.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestLogoutHandlerSuite(t *testing.T) {
	suite.Run(t, &LogoutHandlerSuite{})
}

func (v *LogoutHandlerSuite) TestAuthHandler_LogoutHandler_Success() {
	token := "Bearer validtoken"

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/logout", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.mockAuthService.On("LogoutService", "validtoken").Return(nil)

	v.authHandler.Logout(ctx)

	v.Equal(http.StatusNoContent, w.Code)
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *LogoutHandlerSuite) TestAuthHandler_LogoutHandler_MissingInput() {
	token := ""

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/logout", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Logout(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
}

func (v *LogoutHandlerSuite) TestAuthHandler_LogoutHandler_InvalidFormat() {
	token := "Bearer"

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/logout", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Logout(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
}
