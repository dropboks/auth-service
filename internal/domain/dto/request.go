package dto

import "mime/multipart"

type (
	RegisterRequest struct {
		FullName string                `form:"full_name" binding:"required"`
		Image    *multipart.FileHeader `form:"image" binding:"required"`
		Email    string                `form:"email" binding:"required"`
		Password string                `form:"password" binding:"required"`
	}
	LoginRequest struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	ResendVerificationRequest struct {
		Email string `json:"email" binding:"required"`
	}
	VerifyOTPRequest struct {
		Email string `json:"email" binding:"required"`
		OTP   string `json:"otp" binding:"required"`
	}
)
