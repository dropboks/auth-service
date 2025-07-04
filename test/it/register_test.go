package service_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/dropboks/auth-service/cmd/bootstrap"
	"github.com/dropboks/auth-service/cmd/server"
	"github.com/dropboks/auth-service/config/env"
	"github.com/dropboks/auth-service/internal/infrastructure/grpc"
	"github.com/dropboks/auth-service/test/helper"
	"github.com/dropboks/proto-user/pkg/upb"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type RegisterITSuite struct {
	suite.Suite
	ctx context.Context

	network              *testcontainers.DockerNetwork
	pgContainer          *helper.PostgresContainer
	redisContainer       *helper.RedisContainer
	minioContainer       *helper.MinioContainer
	natsContainer        *helper.NatsContainer
	userServiceContainer *helper.UserServiceContainer
	fileServiceContainer *helper.FileServiceContainer

	userServiceClient upb.UserServiceClient
}

func (r *RegisterITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for RegisterITSuite")
	r.ctx = context.Background()
	gin.SetMode(gin.TestMode)
	os.Setenv("ENV", "test")
	env.Load()

	// spawn sharedNetwork
	r.network = helper.StartNetwork(r.ctx)

	// spawn posgresql
	pgContainer, err := helper.StartPostgresContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	r.pgContainer = pgContainer

	// spawn redis
	rContainer, err := helper.StartRedisContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	r.redisContainer = rContainer

	// spawn minio
	mContainer, err := helper.StartMinioContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	r.minioContainer = mContainer

	// spawn nats
	nContainer, err := helper.StartNatsContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	r.natsContainer = nContainer

	// spawn user service
	uContainer, err := helper.StartUserServiceContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	r.userServiceContainer = uContainer

	// spawn file service
	fContainer, err := helper.StartFileServiceContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	r.fileServiceContainer = fContainer

	grpcManager := grpc.NewGRPCClientManager()
	r.userServiceClient = grpc.NewUserServiceConnection(grpcManager)

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (r *RegisterITSuite) TearDownSuite() {
	if err := r.pgContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
	if err := r.redisContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := r.minioContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := r.natsContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := r.userServiceContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := r.fileServiceContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}

	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for RegisterITSuite")
}
func TestRegisterITSuite(t *testing.T) {
	suite.Run(t, &RegisterITSuite{})
}

func (r *RegisterITSuite) TestRegisterIT_Success() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusCreated, response.StatusCode)
	r.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_MissingBody() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "invalid input")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_EmailAlreadyExist() {
	imageName := "image-name"
	user := &upb.User{
		Id:               "user-id-1",
		FullName:         "test-user",
		Image:            &imageName,
		Email:            "test1@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}
	_, err := r.userServiceClient.CreateUser(r.ctx, user)
	r.NoError(err)

	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-user")
	_ = formWriter.WriteField("email", "test1@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusConflict, response.StatusCode)
	r.Contains(string(byteBody), "user with this email exist")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_WrongExtension() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test2@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.webp")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "error file extension, support jpg, jpeg, and png")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_LimitSizeExceeded() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test3@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")
	fileWriter, _ := formWriter.CreateFormFile("image", "test.png")
	largeData := make([]byte, 8*1024*1024)
	_, err := fileWriter.Write(largeData)
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "max size exceeded: 6mb")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_PasswordAndConfirmPasswordDoesntMatch() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test4@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password1234")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "password and confirm password doesn't match")
	response.Body.Close()
}
