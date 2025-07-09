package dto

import "errors"

var (
	LOGIN_SUCCESS                = "Login Success"
	VERIFICATION_SUCCESS         = "Verification Success"
	REGISTER_SUCCESS             = "Register Success. Check your email for verification."
	RESEND_VERIFICATION_SUCCESS  = "Check your email for verification"
	OTP_VERIFICATION_SUCCESS     = "OTP is Valid"
	OTP_SENT_SUCCESS             = "OTP Has been sent to linked email"
	RESET_PASSWORD_EMAIL_SUCCESS = "Reset password email has been sent"
	CHANGE_PASSWORD_SUCCESS      = "password changed"
)

var (
	Err_BAD_REQUEST                       = errors.New("invalid input")
	Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH = errors.New("password and confirm password doesn't match")
	Err_BAD_REQUEST_WRONG_EXTENSION       = errors.New("error file extension, support jpg, jpeg, and png")
	Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED   = errors.New("max size exceeded: 6mb")

	Err_CONFLICT_EMAIL_EXIST           = errors.New("user with this email exist")
	Err_CONFLICT_USER_ALREADY_VERIFIED = errors.New("user is already verified")

	Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH = errors.New("email or password is wrong")
	Err_UNAUTHORIZED_JWT_INVALID           = errors.New("token is invalid")
	Err_UNAUTHORIZED_TOKEN_INVALID         = errors.New("token is invalid")
	Err_UNAUTHORIZED_USER_NOT_VERIFIED     = errors.New("user is not verified")
	Err_UNAUTHORIZED_2FA_DISABLED          = errors.New("2FA is disabled")
	Err_UNAUTHORIZED_OTP_INVALID           = errors.New("OTP is invalid")

	Err_NOTFOUND_USER_NOT_FOUND = errors.New("user not found")
	Err_NOTFOUND_KEY_NOTFOUND   = errors.New("resource is not found")

	Err_INTENAL_JWT_SIGNING         = errors.New("jwt error signing")
	Err_INTERNAL_SET_RESOURCE       = errors.New("failed save resource")
	Err_INTERNAL_DELETE_RESOURCE    = errors.New("failed to delete resource")
	Err_INTERNAL_GET_RESOURCE       = errors.New("failed to get resource")
	Err_INTERNAL_CONVERT_IMAGE      = errors.New("error processing image")
	Err_INTERNAL_GENERATE_TOKEN     = errors.New("error generate verification token")
	Err_INTERNAL_GENERATE_OTP       = errors.New("error generate OTP")
	Err_INTERNAL_PUBLISH_MESSAGE    = errors.New("error publish email")
	Err_INTERNAL_FAILED_BUILD_QUERY = errors.New("failed to build query")
	Err_INTERNAL_FAILED_SCAN_USER   = errors.New("failed to scan user")
)
