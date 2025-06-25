package handler

import (
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine, ah AuthHandler) *gin.RouterGroup {
	auth := r.Group("/auth")
	{
		auth.POST("/login", ah.Login)
		auth.POST("/register", ah.Register)
		auth.POST("/verify", ah.Verify)
		auth.POST("/logout", ah.Logout)
		auth.GET("/verify-email", ah.VerifyEmail)
	}
	return auth
}
