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

type VerifyITSuite struct {
	suite.Suite
	ctx context.Context

	network              *testcontainers.DockerNetwork
	pgContainer          *helper.PostgresContainer
	redisContainer       *helper.RedisContainer
	natsContainer        *helper.NatsContainer
	userServiceContainer *helper.UserServiceContainer

	userServiceClient upb.UserServiceClient
}

func (v *VerifyITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for VerifyITSuite")
	v.ctx = context.Background()
	gin.SetMode(gin.TestMode)
	os.Setenv("ENV", "test")
	env.Load()

	// spawn sharedNetwork
	v.network = helper.StartNetwork(v.ctx)

	// spawn posgresql
	pgContainer, err := helper.StartPostgresContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	v.pgContainer = pgContainer

	// spawn redis
	rContainer, err := helper.StartRedisContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	v.redisContainer = rContainer

	// spawn nats
	nContainer, err := helper.StartNatsContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	v.natsContainer = nContainer

	// spawn user service
	uContainer, err := helper.StartUserServiceContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	v.userServiceContainer = uContainer

	grpcManager := grpc.NewGRPCClientManager()
	v.userServiceClient = grpc.NewUserServiceConnection(grpcManager)

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (v *VerifyITSuite) TearDownSuite() {
	if err := v.pgContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
	if err := v.redisContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := v.natsContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := v.userServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for VerifyITSuite")
}
func TestVerifyITSuite(t *testing.T) {
	suite.Run(t, &VerifyITSuite{})
}

func (v *VerifyITSuite) TestVerifyIT_Success() {
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
	_, err := v.userServiceClient.CreateUser(v.ctx, user)
	v.NoError(err)
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    "test1@example.com",
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	v.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	v.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	v.NoError(err)
	defer response.Body.Close()

	var respData map[string]interface{}
	err = json.Unmarshal(byteBody, &respData)
	v.NoError(err)

	jwt, ok := respData["data"].(string)
	v.True(ok, "expected jwt token in data field")

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	v.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)
	defer verifyResp.Body.Close()

	v.Equal(http.StatusNoContent, verifyResp.StatusCode)
}

func (v *VerifyITSuite) TestVerifyIT_MissingToken() {

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	v.NoError(err)

	client := http.Client{}
	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	v.NoError(err)

	v.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	v.Contains(string(byteBody), "Token is missing")
}

func (v *VerifyITSuite) TestVerifyIT_InvalidFormat() {

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	verifyReq.Header.Set("Authorization", "Bearer")
	v.NoError(err)

	client := http.Client{}
	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	v.NoError(err)

	v.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	v.Contains(string(byteBody), "Invalid token format")
}

func (v *VerifyITSuite) TestVerifyIT_InvalidToken() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)
	v.NoError(err)

	client := http.Client{}
	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	v.NoError(err)

	v.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	v.Contains(string(byteBody), "token is invalid")
}

func (v *VerifyITSuite) TestVerifyIT_UnmatchTokenWithTokenInTheState() {
	imageName := "image-name"
	user := &upb.User{
		Id:               "user-id-2",
		FullName:         "test-user2",
		Image:            &imageName,
		Email:            "test2@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}
	_, err := v.userServiceClient.CreateUser(v.ctx, user)
	v.NoError(err)

	reqBody1 := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody1).Encode(gin.H{
		"email":    "test2@example.com",
		"password": "password123",
	})
	req1, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody1)
	v.NoError(err)

	client := http.Client{}
	resp1, err := client.Do(req1)
	v.NoError(err)

	defer resp1.Body.Close()
	body1, err := io.ReadAll(resp1.Body)
	v.NoError(err)

	var respData1 map[string]interface{}
	err = json.Unmarshal(body1, &respData1)
	v.NoError(err)

	jwt1, ok := respData1["data"].(string)
	v.True(ok, "expected jwt token in data field")

	reqBody2 := &bytes.Buffer{}
	_ = json.NewEncoder(reqBody2).Encode(gin.H{
		"email":    "test2@example.com",
		"password": "password123",
	})
	req2, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody2)
	v.NoError(err)

	resp2, err := client.Do(req2)
	v.NoError(err)
	defer resp2.Body.Close()

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt1)
	v.NoError(err)

	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)

	byteBody, err := io.ReadAll(verifyResp.Body)
	v.NoError(err)

	v.Equal(http.StatusUnauthorized, verifyResp.StatusCode)
	v.Contains(string(byteBody), "token is invalid")
}
