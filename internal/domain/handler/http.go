package handler

import (
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine, ah AuthHandler) *gin.Engine {
	{
		r.POST("/login", ah.Login)
		r.POST("/register", ah.Register)
		r.POST("/verify", ah.Verify)
		r.POST("/logout", ah.Logout)
		r.GET("/verify-email", ah.VerifyEmail)
		r.POST("/resend-verification-email", ah.ResendVerficationEmail)
		r.POST("/verify-otp", ah.VerifyOTP)
	}
	return r
}
