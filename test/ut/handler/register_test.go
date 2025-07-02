package handler_test

import (
	"bytes"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/handler"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type RegisterHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
}

func (r *RegisterHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	r.mockAuthService = mockedAuthService
	r.authHandler = handler.New(mockedAuthService, logger)
}

func (r *RegisterHandlerSuite) SetupTest() {
	r.mockAuthService.ExpectedCalls = nil
	r.mockAuthService.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestRegisterHandlerSuite(t *testing.T) {
	suite.Run(t, &RegisterHandlerSuite{})
}

func (r *RegisterHandlerSuite) TestAuthHandler_RegisterHandler_Success() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	input := dto.RegisterRequest{
		FullName:        "test-full-name",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	request := httptest.NewRequest(http.MethodPost, "/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("RegisterService", mock.MatchedBy(func(req dto.RegisterRequest) bool {
		return req.FullName == input.FullName &&
			req.Email == input.Email &&
			req.Password == input.Password &&
			req.ConfirmPassword == input.ConfirmPassword &&
			req.Image != nil
	})).Return(nil)

	r.authHandler.Register(ctx)

	r.Equal(201, w.Code)
	r.Contains(w.Body.String(), "Register Success. Check your email for verification.")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *RegisterHandlerSuite) TestAuthHandler_RegisterHandler_MissingInput() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request := httptest.NewRequest(http.MethodPost, "/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.authHandler.Register(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "invalid input")
}

func (r *RegisterHandlerSuite) TestAuthHandler_RegisterHandler_EmailAlreadyExist() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	input := dto.RegisterRequest{
		FullName:        "test-full-name",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	request := httptest.NewRequest(http.MethodPost, "/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("RegisterService", mock.MatchedBy(func(req dto.RegisterRequest) bool {
		return req.FullName == input.FullName &&
			req.Email == input.Email &&
			req.Password == input.Password &&
			req.ConfirmPassword == input.ConfirmPassword &&
			req.Image != nil
	})).Return(dto.Err_CONFLICT_EMAIL_EXIST)

	r.authHandler.Register(ctx)

	r.Equal(409, w.Code)
	r.Contains(w.Body.String(), "user with this email exist")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *RegisterHandlerSuite) TestAuthHandler_RegisterHandler_WrongImageExtension() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	input := dto.RegisterRequest{
		FullName:        "test-full-name",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	request := httptest.NewRequest(http.MethodPost, "/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("RegisterService", mock.MatchedBy(func(req dto.RegisterRequest) bool {
		return req.FullName == input.FullName &&
			req.Email == input.Email &&
			req.Password == input.Password &&
			req.ConfirmPassword == input.ConfirmPassword &&
			req.Image != nil
	})).Return(dto.Err_BAD_REQUEST_WRONG_EXTENSION)

	r.authHandler.Register(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "error file extension, support jpg, jpeg, and png")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *RegisterHandlerSuite) TestAuthHandler_RegisterHandler_ImageSizeExceeded() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	input := dto.RegisterRequest{
		FullName:        "test-full-name",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	request := httptest.NewRequest(http.MethodPost, "/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("RegisterService", mock.MatchedBy(func(req dto.RegisterRequest) bool {
		return req.FullName == input.FullName &&
			req.Email == input.Email &&
			req.Password == input.Password &&
			req.ConfirmPassword == input.ConfirmPassword &&
			req.Image != nil
	})).Return(dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED)

	r.authHandler.Register(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "max size exceeded: 6mb")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *RegisterHandlerSuite) TestAuthHandler_RegisterHandler_PasswordAndConfirmPasswordNotMatch() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password1234")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	input := dto.RegisterRequest{
		FullName:        "test-full-name",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password1234",
	}

	request := httptest.NewRequest(http.MethodPost, "/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("RegisterService", mock.MatchedBy(func(req dto.RegisterRequest) bool {
		return req.FullName == input.FullName &&
			req.Email == input.Email &&
			req.Password == input.Password &&
			req.ConfirmPassword == input.ConfirmPassword &&
			req.Image != nil
	})).Return(dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH)

	r.authHandler.Register(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "password and confirm password doesn't match")
	r.mockAuthService.AssertExpectations(r.T())
}
