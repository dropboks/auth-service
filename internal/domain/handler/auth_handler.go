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
		VerifyEmail(ctx *gin.Context)
		ResendVerficationEmail(ctx *gin.Context)
		VerifyOTP(ctx *gin.Context)
		ResendVerificationOTP(ctx *gin.Context)
		ResetPassword(ctx *gin.Context)
		ChangePassword(ctx *gin.Context)
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

func (a *authHandler) ChangePassword(ctx *gin.Context) {
	userId := ctx.Query("userid")
	resetPasswordtoken := ctx.Query("resetPasswordToken")
	if userId == "" || resetPasswordtoken == "" {
		a.logger.Error().Msg("missing userId or token")
		res := utils.ReturnResponseError(http.StatusBadRequest, "invalid input")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	var req dto.ChangePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		a.logger.Error().Err(err).Msg("missing body request")
		res := utils.ReturnResponseError(400, "invalid input")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	if err := a.authService.ChangePasswordService(userId, resetPasswordtoken, &req); err != nil {
		switch err {
		case dto.Err_UNAUTHORIZED_TOKEN_INVALID:
			res := utils.ReturnResponseError(401, "invalid token")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH:
			res := utils.ReturnResponseError(400, err.Error())
			ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		if code == codes.NotFound {
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	res := utils.ReturnResponseSuccess(200, dto.CHANGE_PASSWORD_SUCCESS)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) ResetPassword(ctx *gin.Context) {
	var req dto.ResetPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		a.logger.Error().Err(err).Msg("bad request")
		res := utils.ReturnResponseError(http.StatusBadRequest, "missing email")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	if err := a.authService.ResetPasswordService(req.Email); err != nil {
		a.logger.Error().Err(err).Msg("failed to reset")
		code := status.Code(err)
		message := status.Convert(err).Message()
		if code == codes.NotFound {
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}

	res := utils.ReturnResponseSuccess(200, dto.RESET_PASSWORD_EMAIL_SUCCESS)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) ResendVerificationOTP(ctx *gin.Context) {
	var req dto.ResendVerificationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		res := utils.ReturnResponseError(http.StatusBadRequest, "missing email")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	if err := a.authService.ResendVerificationOTPService(req.Email); err != nil {
		if err == dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED || err == dto.Err_UNAUTHORIZED_2FA_DISABLED {
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		switch code {
		case codes.NotFound:
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		case codes.Internal:
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	res := utils.ReturnResponseSuccess(200, dto.OTP_SENT_SUCCESS)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) VerifyOTP(ctx *gin.Context) {
	var req dto.VerifyOTPRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		res := utils.ReturnResponseError(http.StatusBadRequest, "invalid input")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	token, err := a.authService.VerifyOTPService(req.OTP, req.Email)
	if err != nil {
		switch err {
		case dto.Err_UNAUTHORIZED_OTP_INVALID:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_NOTFOUND_KEY_NOTFOUND:
			res := utils.ReturnResponseError(404, "otp is invalid")
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		switch code {
		case codes.NotFound:
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		case codes.Internal:
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	res := utils.ReturnResponseSuccess(200, dto.OTP_VERIFICATION_SUCCESS, token)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) ResendVerficationEmail(ctx *gin.Context) {
	var req dto.ResendVerificationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		res := utils.ReturnResponseError(http.StatusBadRequest, "missing email")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	if err := a.authService.ResendVerificationService(req.Email); err != nil {
		switch err {
		case dto.Err_CONFLICT_USER_ALREADY_VERIFIED:
			res := utils.ReturnResponseError(409, err.Error())
			ctx.AbortWithStatusJSON(http.StatusConflict, res)
			return
		case dto.Err_INTERNAL_GENERATE_TOKEN, dto.Err_INTERNAL_PUBLISH_MESSAGE:
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}

		code := status.Code(err)
		message := status.Convert(err).Message()
		switch code {
		case codes.NotFound:
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		case codes.Internal:
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	res := utils.ReturnResponseSuccess(200, dto.RESEND_VERIFICATION_SUCCESS)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) VerifyEmail(ctx *gin.Context) {
	userId := ctx.Query("userid")
	token := ctx.Query("token")
	changeEmailToken := ctx.Query("changeEmailToken")
	if userId == "" || (token == "" && changeEmailToken == "") {
		res := utils.ReturnResponseError(http.StatusBadRequest, "invalid input")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	if err := a.authService.VerifyEmailService(userId, token, changeEmailToken); err != nil {
		switch err {
		case dto.Err_UNAUTHORIZED_TOKEN_INVALID:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_CONFLICT_USER_ALREADY_VERIFIED:
			res := utils.ReturnResponseError(409, err.Error())
			ctx.AbortWithStatusJSON(http.StatusConflict, res)
			return
		case dto.Err_NOTFOUND_KEY_NOTFOUND:
			res := utils.ReturnResponseError(404, "verification token is not found")
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		case dto.Err_INTERNAL_DELETE_RESOURCE:
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		switch code {
		case codes.NotFound:
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		case codes.Internal:
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	res := utils.ReturnResponseSuccess(200, dto.VERIFICATION_SUCCESS)
	ctx.JSON(http.StatusOK, res)
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
		switch err {
		case dto.Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		switch code {
		case codes.NotFound:
			res := utils.ReturnResponseError(404, message)
			ctx.AbortWithStatusJSON(http.StatusNotFound, res)
			return
		case codes.Internal:
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	if token == "" {
		res := utils.ReturnResponseSuccess(200, dto.OTP_SENT_SUCCESS)
		ctx.JSON(http.StatusOK, res)
		return
	}
	res := utils.ReturnResponseSuccess(200, dto.LOGIN_SUCCESS, token)
	ctx.JSON(http.StatusOK, res)
}

func (a *authHandler) Register(ctx *gin.Context) {
	var req dto.RegisterRequest
	if err := ctx.ShouldBind(&req); err != nil {
		a.logger.Error().Err(err).Msg("Bad Request")
		res := utils.ReturnResponseError(400, dto.Err_BAD_REQUEST.Error())
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}
	err := a.authService.RegisterService(req)
	if err != nil {
		switch err {
		case dto.Err_CONFLICT_EMAIL_EXIST:
			res := utils.ReturnResponseError(409, err.Error())
			ctx.AbortWithStatusJSON(http.StatusConflict, res)
			return
		case dto.Err_INTERNAL_CONVERT_IMAGE:
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		case dto.Err_BAD_REQUEST_WRONG_EXTENSION:
			res := utils.ReturnResponseError(400, err.Error())
			ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
			return
		case dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED:
			res := utils.ReturnResponseError(400, err.Error())
			ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
			return
		case dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH:
			res := utils.ReturnResponseError(400, err.Error())
			ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
			return
		case dto.Err_INTENAL_JWT_SIGNING:
			res := utils.ReturnResponseError(500, err.Error())
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		case dto.Err_INTERNAL_SET_RESOURCE:
			res := utils.ReturnResponseError(500, "failed to set verification token")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		case dto.Err_INTERNAL_GENERATE_TOKEN:
			res := utils.ReturnResponseError(500, "failed to set verification token")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		code := status.Code(err)
		message := status.Convert(err).Message()
		if code == codes.Internal {
			res := utils.ReturnResponseError(500, message)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	res := utils.ReturnResponseSuccess(201, dto.REGISTER_SUCCESS)
	ctx.JSON(http.StatusCreated, res)
}

func (a *authHandler) Verify(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Token is missing")
		return
	}
	if len(token) < 7 {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid token format")
		return
	}
	token = token[7:]
	userId, err := a.authService.VerifyService(token)
	if err != nil {
		switch err {
		case dto.Err_NOTFOUND_KEY_NOTFOUND:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_UNAUTHORIZED_JWT_INVALID:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_INTERNAL_GET_RESOURCE:
			res := utils.ReturnResponseError(500, "failed to get token")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}
		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	ctx.Header("User-Data", fmt.Sprintf(`{"user_id":"%s"}`, userId))
	ctx.AbortWithStatus(http.StatusNoContent)
}

func (a *authHandler) Logout(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Token is missing")
		return
	}
	if len(token) < 7 {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid token format")
		return
	}
	token = token[7:]
	err := a.authService.LogoutService(token)
	if err != nil {
		switch err {
		case dto.Err_UNAUTHORIZED_JWT_INVALID:
			res := utils.ReturnResponseError(401, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		case dto.Err_INTERNAL_DELETE_RESOURCE:
			res := utils.ReturnResponseError(500, "failed to delete token")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}

		res := utils.ReturnResponseError(500, err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return
	}
	ctx.AbortWithStatus(http.StatusNoContent)
}
