package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
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

type LoginITSuite struct {
	suite.Suite
	ctx context.Context

	network              *testcontainers.DockerNetwork
	pgContainer          *helper.PostgresContainer
	redisContainer       *helper.RedisContainer
	natsContainer        *helper.NatsContainer
	userServiceContainer *helper.UserServiceContainer

	userServiceClient upb.UserServiceClient
}

func (l *LoginITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for LoginITSuite")
	l.ctx = context.Background()
	gin.SetMode(gin.TestMode)
	os.Setenv("ENV", "test")
	env.Load()

	// spawn sharedNetwork
	l.network = helper.StartNetwork(l.ctx)

	// spawn posgresql
	pgContainer, err := helper.StartPostgresContainer(l.ctx, l.network.Name)
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	l.pgContainer = pgContainer

	// spawn redis
	rContainer, err := helper.StartRedisContainer(l.ctx, l.network.Name)
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	l.redisContainer = rContainer

	// spawn nats
	nContainer, err := helper.StartNatsContainer(l.ctx, l.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	l.natsContainer = nContainer

	uContainer, err := helper.StartUserServiceContainer(l.ctx, l.network.Name)
	if err != nil {
		log.Fatal(err)
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	l.userServiceContainer = uContainer

	grpcManager := grpc.NewGRPCClientManager()
	l.userServiceClient = grpc.NewUserServiceConnection(grpcManager)

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (l *LoginITSuite) TearDownSuite() {
	if err := l.redisContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := l.natsContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := l.userServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := l.pgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for LoginITSuite")
}
func TestLoginITSuite(t *testing.T) {
	suite.Run(t, &LoginITSuite{})
}

func (l *LoginITSuite) TestLoginIT_Success() {
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
	_, err := l.userServiceClient.CreateUser(l.ctx, user)
	l.NoError(err)

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "test1@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "Login Success")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_Success2FA() {
	imageName := "image-name"
	user := &upb.User{
		Id:               "user-id-6",
		FullName:         "test-user",
		Image:            &imageName,
		Email:            "test6@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}
	_, err := l.userServiceClient.CreateUser(l.ctx, user)
	l.NoError(err)

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "test6@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "OTP Has been sent to linked email")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_MissingBody() {

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": "test2@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusBadRequest, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "invalid input")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_NotVerified() {
	imageName := "image-name"
	user := &upb.User{
		Id:               "user-id-3",
		FullName:         "test-user",
		Image:            &imageName,
		Email:            "test3@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}
	_, err := l.userServiceClient.CreateUser(l.ctx, user)
	l.NoError(err)

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "test3@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusUnauthorized, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "user is not verified")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_PasswordDoesntMatch() {
	imageName := "image-name"
	user := &upb.User{
		Id:               "user-id-4",
		FullName:         "test-user",
		Image:            &imageName,
		Email:            "test4@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}
	_, err := l.userServiceClient.CreateUser(l.ctx, user)
	l.NoError(err)

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "test4@example.com",
		"password": "password1234",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusUnauthorized, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "email or password is wrong")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_UserNotfound() {

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "test5@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusNotFound, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "user not found")
	response.Body.Close()
}
