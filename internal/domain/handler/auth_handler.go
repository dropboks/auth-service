package handler

import (
	"fmt"
	"net/http"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/sharedlib/utils"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	AuthHandler interface {
		Login(ctx *gin.Context)
		Register(ctx *gin.Context)
		Logout(ctx *gin.Context)
		Verify(ctx *gin.Context)
	}
	authHandler struct {
		authService service.AuthService
		logger      zerolog.Logger
	}
)

func New(authService service.AuthService, logger zerolog.Logger) AuthHandler {
	return &authHandler{
		authService: authService,
		logger:      logger,
	}
}

func (a *authHandler) Login(ctx *gin.Context) {
	var req dto.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		a.logger.Error().Err(err).Msg("Bad Request")
		res := utils.ReturnResponseError(400, dto.Err_BAD_REQUEST.Error())
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	token, err := a.authService.LoginService(req)
	if err != nil {
		if err == dto.Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH {
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		} else if err == dto.Err_INTENAL_JWT_SIGNING {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		} else if err == dto.Err_INTERNAL_SET_TOKEN {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		if code == codes.Internal {
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		} else if code == codes.NotFound {
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		}
	}
	res := utils.ReturnResponseSuccess(200, dto.LOGIN_SUCCESS, token)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) Logout(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Token is missing")
		return
	}
	token = token[7:]
	err := a.authService.LogoutService(token)
	if err != nil {
		if err == dto.Err_INTERNAL_DELETE_TOKEN {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
	}
	ctx.Status(http.StatusNoContent)
}

func (a *authHandler) Register(ctx *gin.Context) {
	var req dto.RegisterRequest
	if err := ctx.ShouldBind(&req); err != nil {
		a.logger.Error().Err(err).Msg("Bad Request")
		res := utils.ReturnResponseError(400, dto.Err_BAD_REQUEST.Error())
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	token, err := a.authService.RegisterService(req)
	if err != nil {
		if err == dto.Err_CONFLICT_EMAIL_EXIST {
			res := utils.ReturnResponseError(409, err.Error())
			ctx.AbortWithStatusJSON(http.StatusConflict, res)
			return
		} else if err == dto.Err_INTERNAL_CONVERT_IMAGE {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		} else if err == dto.Err_INTENAL_JWT_SIGNING {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		} else if err == dto.Err_INTERNAL_SET_TOKEN {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		} else if err == dto.Err_BAD_REQUEST_WRONG_EXTENTION {
			res := utils.ReturnResponseError(400, err.Error())
			ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
			return
		} else if err == dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED {
			res := utils.ReturnResponseError(400, err.Error())
			ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		if code == codes.Internal {
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
	}
	res := utils.ReturnResponseSuccess(200, dto.REGISTER_SUCCESS, token)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) Verify(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Token is missing")
		return
	}
	token = token[7:]
	userId, err := a.authService.VerifyService(token)
	if err != nil {
		if err == dto.Err_NOTFOUND_KEY_NOTFOUND {
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		} else if err == dto.Err_INTERNAL_GET_TOKEN {
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		} else if err == dto.Err_UNAUTHORIZED_JWT_INVALID {
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}
	}
	ctx.Header("User-Data", fmt.Sprintf(`{"user_id":"%s"}`, userId))
	ctx.Status(http.StatusNoContent)
}
