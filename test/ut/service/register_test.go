package service_test

import (
	"bytes"
	"mime/multipart"
	"testing"
	"time"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/service"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/dropboks/proto-file/pkg/fpb"
	upb "github.com/dropboks/proto-user/pkg/upb"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegisterServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (r *RegisterServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	// logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	r.mockAuthRepo = mockAuthRepo
	r.mockUserClient = mockUserClient
	r.mockFileClient = mockFileClient
	r.mockJetStream = mockJetStream
	r.mockGenerator = mockGenerator
	r.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (r *RegisterServiceSuite) SetupTest() {
	r.mockAuthRepo.ExpectedCalls = nil
	r.mockUserClient.ExpectedCalls = nil
	r.mockFileClient.ExpectedCalls = nil
	r.mockJetStream.ExpectedCalls = nil
	r.mockGenerator.ExpectedCalls = nil
	r.mockAuthRepo.Calls = nil
	r.mockUserClient.Calls = nil
	r.mockFileClient.Calls = nil
	r.mockJetStream.Calls = nil
	r.mockGenerator.Calls = nil
}

func TestRegisterServiceSuite(t *testing.T) {
	suite.Run(t, &RegisterServiceSuite{})
}
func (r *RegisterServiceSuite) TestAuthService_RegisterService_Success() {
	imageData := bytes.Repeat([]byte("test"), 1024)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("image", "test_image.jpg")
	part.Write(imageData)
	writer.Close()

	reader := multipart.NewReader(&buf, writer.Boundary())
	form, _ := reader.ReadForm(32 << 20)
	fileHeader := form.File["image"][0]

	registerReq := dto.RegisterRequest{
		FullName:        "test_fullname",
		Image:           fileHeader,
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	mockPubAck := &jetstream.PubAck{
		Stream:   "test-stream",
		Sequence: 1,
	}

	r.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == registerReq.Email
	})).Return(nil, status.Error(codes.NotFound, "user not found"))

	r.mockFileClient.On("SaveProfileImage", mock.Anything, mock.Anything).Return(&fpb.ImageName{Name: "saved-image-name.jpg"}, nil)
	r.mockGenerator.On("GenerateUUID").Return("uuid-generated")
	r.mockUserClient.On("CreateUser", mock.Anything, mock.Anything).Return(&upb.Status{Success: true}, nil)
	r.mockGenerator.On("GenerateToken", mock.Anything).Return("token-generated", nil)
	r.mockAuthRepo.On("SetResource", mock.Anything, "verificationToken:uuid-generated", mock.AnythingOfType("string"), mock.Anything).Return(nil)
	r.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)

	err := r.authService.RegisterService(registerReq)

	assert.NoError(r.T(), err)
	r.mockUserClient.AssertExpectations(r.T())
	r.mockFileClient.AssertExpectations(r.T())
	r.mockAuthRepo.AssertExpectations(r.T())
	r.mockGenerator.AssertExpectations(r.T())

	time.Sleep(100 * time.Millisecond)
	r.mockJetStream.AssertExpectations(r.T())
}
func (r *RegisterServiceSuite) TestAuthService_RegisterService_PasswordNotMatch() {

	registerReq := dto.RegisterRequest{
		FullName:        "test_fullname",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password1234",
		ConfirmPassword: "password123",
	}

	err := r.authService.RegisterService(registerReq)

	assert.Error(r.T(), err)
}
func (r *RegisterServiceSuite) TestAuthService_RegisterService_WrongImageExtension() {
	imageData := bytes.Repeat([]byte("test"), 1024)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("image", "test_image.pdf")
	part.Write(imageData)
	writer.Close()

	reader := multipart.NewReader(&buf, writer.Boundary())
	form, _ := reader.ReadForm(32 << 20)
	fileHeader := form.File["image"][0]

	registerReq := dto.RegisterRequest{
		FullName:        "test_fullname",
		Image:           fileHeader,
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	err := r.authService.RegisterService(registerReq)

	assert.Error(r.T(), err)
}
func (r *RegisterServiceSuite) TestAuthService_RegisterService_ImageSizeExceeded() {
	imageData := bytes.Repeat([]byte("test"), 8*1024*1024)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("image", "test_image.jpg")
	part.Write(imageData)
	writer.Close()

	reader := multipart.NewReader(&buf, writer.Boundary())
	form, _ := reader.ReadForm(32 << 20)
	fileHeader := form.File["image"][0]

	registerReq := dto.RegisterRequest{
		FullName:        "test_fullname",
		Image:           fileHeader,
		Email:           "test@example.com",
		Password:        "password123",
		ConfirmPassword: "password123",
	}

	err := r.authService.RegisterService(registerReq)
	assert.Error(r.T(), err)
}
func (r *RegisterServiceSuite) TestAuthService_RegisterService_EmailAlreadyExist() {

	registerReq := dto.RegisterRequest{
		FullName:        "test_fullname",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password1234",
		ConfirmPassword: "password1234",
	}

	mockUser := &upb.User{
		Id:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}
	r.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == registerReq.Email
	})).Return(mockUser, nil)

	err := r.authService.RegisterService(registerReq)
	assert.Error(r.T(), err)

	r.mockUserClient.AssertExpectations(r.T())
}
