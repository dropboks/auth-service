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

type LogoutITSuite struct {
	suite.Suite
	ctx context.Context

	network              *testcontainers.DockerNetwork
	pgContainer          *helper.PostgresContainer
	redisContainer       *helper.RedisContainer
	natsContainer        *helper.NatsContainer
	userServiceContainer *helper.UserServiceContainer

	userServiceClient upb.UserServiceClient
}

func (l *LogoutITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for LogoutITSuite")
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

	// spawn user service
	uContainer, err := helper.StartUserServiceContainer(l.ctx, l.network.Name)
	if err != nil {
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
func (l *LogoutITSuite) TearDownSuite() {
	if err := l.pgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
	if err := l.redisContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := l.natsContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := l.userServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for LogoutITSuite")
}
func TestLogoutITSuite(t *testing.T) {
	suite.Run(t, &LogoutITSuite{})
}

func (l *LogoutITSuite) TestLogoutIT_Success() {
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

	l.NoError(err)
	defer response.Body.Close()

	var respData map[string]interface{}
	err = json.Unmarshal(byteBody, &respData)
	l.NoError(err)

	jwt, ok := respData["data"].(string)
	l.True(ok, "expected jwt token in data field")

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/logout", nil)
	l.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	l.NoError(err)
	defer verifyResp.Body.Close()

	l.Equal(http.StatusNoContent, verifyResp.StatusCode)
}

func (l *LogoutITSuite) TestLogoutIT_MissingToken() {

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/logout", nil)
	l.NoError(err)

	client := http.Client{}
	verifyResp, err := client.Do(verifyReq)
	l.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	l.NoError(err)

	l.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	l.Contains(string(byteBody), "Token is missing")
}

func (l *LogoutITSuite) TestLogoutIT_InvalidFormat() {

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/logout", nil)
	verifyReq.Header.Set("Authorization", "Bearer")
	l.NoError(err)

	client := http.Client{}
	verifyResp, err := client.Do(verifyReq)
	l.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	l.NoError(err)

	l.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	l.Contains(string(byteBody), "Invalid token format")
}

func (l *LogoutITSuite) TestLogoutIT_InvalidToken() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/logout", nil)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)
	l.NoError(err)

	client := http.Client{}
	verifyResp, err := client.Do(verifyReq)
	l.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	l.NoError(err)

	l.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	l.Contains(string(byteBody), "token is invalid")
}
