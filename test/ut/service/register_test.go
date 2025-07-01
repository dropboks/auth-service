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
	mockJetStream  *mocks.MockJetStreamInfra
	mockGenerator  *mocks.MockRandomGenerator
}

func (l *RegisterServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockJetStreamInfra)
	mockGenerator := new(mocks.MockRandomGenerator)

	logger := zerolog.Nop()
	// logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	l.mockAuthRepo = mockAuthRepo
	l.mockUserClient = mockUserClient
	l.mockFileClient = mockFileClient
	l.mockJetStream = mockJetStream
	l.mockGenerator = mockGenerator
	l.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator)
}

func (l *RegisterServiceSuite) SetupTest() {
	l.mockAuthRepo.ExpectedCalls = nil
	l.mockUserClient.ExpectedCalls = nil
	l.mockFileClient.ExpectedCalls = nil
	l.mockJetStream.ExpectedCalls = nil
	l.mockGenerator.ExpectedCalls = nil
	l.mockAuthRepo.Calls = nil
	l.mockUserClient.Calls = nil
	l.mockFileClient.Calls = nil
	l.mockJetStream.Calls = nil
	l.mockGenerator.Calls = nil
}

func TestRegisterServiceSuite(t *testing.T) {
	suite.Run(t, &RegisterServiceSuite{})
}
func (l *RegisterServiceSuite) TestAuthService_RegisterService_Success() {
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

	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == registerReq.Email
	})).Return(nil, status.Error(codes.NotFound, "user not found"))

	l.mockFileClient.On("SaveProfileImage", mock.Anything, mock.Anything).Return(&fpb.ImageName{Name: "saved-image-name.jpg"}, nil)
	l.mockGenerator.On("GenerateUUID").Return("uuid-generated")
	l.mockUserClient.On("CreateUser", mock.Anything, mock.Anything).Return(&upb.Status{Success: true}, nil)
	l.mockGenerator.On("GenerateToken", mock.Anything).Return("token-generated", nil)
	l.mockAuthRepo.On("SetResource", mock.Anything, "verificationToken:uuid-generated", mock.AnythingOfType("string"), mock.Anything).Return(nil)
	l.mockJetStream.On("Publish", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(mockPubAck, nil)

	err := l.authService.RegisterService(registerReq)

	assert.NoError(l.T(), err)
	l.mockUserClient.AssertExpectations(l.T())
	l.mockFileClient.AssertExpectations(l.T())
	l.mockAuthRepo.AssertExpectations(l.T())
	l.mockGenerator.AssertExpectations(l.T())

	time.Sleep(100 * time.Millisecond)
	l.mockJetStream.AssertExpectations(l.T())
}
func (l *RegisterServiceSuite) TestAuthService_RegisterService_PasswordNotMatch() {

	registerReq := dto.RegisterRequest{
		FullName:        "test_fullname",
		Image:           &multipart.FileHeader{},
		Email:           "test@example.com",
		Password:        "password1234",
		ConfirmPassword: "password123",
	}

	err := l.authService.RegisterService(registerReq)

	assert.Error(l.T(), err)
}
func (l *RegisterServiceSuite) TestAuthService_RegisterService_WrongImageExtension() {
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

	err := l.authService.RegisterService(registerReq)

	assert.Error(l.T(), err)
}
func (l *RegisterServiceSuite) TestAuthService_RegisterService_ImageSizeExceeded() {
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

	err := l.authService.RegisterService(registerReq)
	assert.Error(l.T(), err)
}
func (l *RegisterServiceSuite) TestAuthService_RegisterService_EmailAlreadyExist() {

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
	l.mockUserClient.On("GetUserByEmail", mock.Anything, mock.MatchedBy(func(email *upb.Email) bool {
		return email.Email == registerReq.Email
	})).Return(mockUser, nil)

	err := l.authService.RegisterService(registerReq)
	assert.Error(l.T(), err)

	l.mockUserClient.AssertExpectations(l.T())
}
