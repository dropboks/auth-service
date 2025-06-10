package dto

import "errors"

var (
	LOGIN_SUCCESS = "Login Success"
	REGISTER_SUCCESS = "Register Success"
)

var (
	Err_BAD_REQUEST = errors.New("bad request in the data")
	Err_BAD_REQUEST_WRONG_EXTENTION = errors.New("error file extension, support jpg, jpeg, and png")
	Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED = errors.New("max size exceeded: 6mb")

	Err_CONFLICT_EMAIL_EXIST = errors.New("user with this email exist")

	Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH = errors.New("password doesn't match")
	Err_UNAUTHORIZED_JWT_INVALID    = errors.New("token is invalid")

	Err_NOTFOUND_KEY_NOTFOUND = errors.New("token is not found")

	Err_INTENAL_JWT_SIGNING   = errors.New("jwt error signing")
	Err_INTERNAL_SET_TOKEN    = errors.New("failed save token")
	Err_INTERNAL_DELETE_TOKEN = errors.New("failed to delete token")
	Err_INTERNAL_GET_TOKEN    = errors.New("failed to get token")
	Err_INTERNAL_CONVERT_IMAGE    = errors.New("error processing image")
)
