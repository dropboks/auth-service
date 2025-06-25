package dto

import "errors"

var (
	LOGIN_SUCCESS               = "Login Success"
	VERIFICATION_SUCCESS        = "Verification Success"
	REGISTER_SUCCESS            = "Register Success. Check your email for verification."
	RESEND_VERIFICATION_SUCCESS = "Check your email for verification"
)

var (
	Err_BAD_REQUEST                     = errors.New("bad request in the data")
	Err_BAD_REQUEST_WRONG_EXTENTION     = errors.New("error file extension, support jpg, jpeg, and png")
	Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED = errors.New("max size exceeded: 6mb")

	Err_CONFLICT_EMAIL_EXIST           = errors.New("user with this email exist")
	Err_CONFLICT_USER_ALREADY_VERIFIED = errors.New("user is already verified")

	Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH      = errors.New("password doesn't match")
	Err_UNAUTHORIZED_JWT_INVALID                = errors.New("token is invalid")
	Err_UNAUTHORIZED_VERIFICATION_TOKEN_INVALID = errors.New("token is invalid")
	Err_UNAUTHORIZED_USER_NOT_VERIFIED          = errors.New("user is not verified")

	Err_NOTFOUND_KEY_NOTFOUND = errors.New("resource is not found")

	Err_INTENAL_JWT_SIGNING      = errors.New("jwt error signing")
	Err_INTERNAL_SET_RESOURCE    = errors.New("failed save resource")
	Err_INTERNAL_DELETE_RESOURCE = errors.New("failed to delete resource")
	Err_INTERNAL_GET_RESOURCE    = errors.New("failed to get resource")
	Err_INTERNAL_CONVERT_IMAGE   = errors.New("error processing image")
	Err_INTERNAL_GENERATE_TOKEN  = errors.New("error generate verification token")
	Err_INTERNAL_GENERATE_OTP    = errors.New("error generate OTP")
	Err_INTERNAL_PUBLISH_MESSAGE = errors.New("error publish email")
)
