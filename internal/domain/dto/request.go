package dto

import "mime/multipart"

type (
	RegisterRequest struct {
		FullName        string                `form:"full_name" binding:"required,min=1,max=100"`
		Image           *multipart.FileHeader `form:"image" `
		Email           string                `form:"email" binding:"required,email"`
		Password        string                `form:"password" binding:"required,min=8"`
		ConfirmPassword string                `form:"confirm_password" binding:"required,min=8"`
	}
	LoginRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}
	ResendVerificationRequest struct {
		Email string `json:"email" binding:"required,email"`
	}
	VerifyOTPRequest struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"`
	}
)
