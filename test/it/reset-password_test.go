package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/dropboks/auth-service/cmd/bootstrap"
	"github.com/dropboks/auth-service/cmd/server"
	"github.com/dropboks/auth-service/config/env"
	"github.com/dropboks/auth-service/test/helper"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type ResetPasswordITSuite struct {
	suite.Suite
	ctx context.Context

	network                      *testcontainers.DockerNetwork
	pgContainer                  *helper.PostgresContainer
	redisContainer               *helper.RedisContainer
	minioContainer               *helper.MinioContainer
	natsContainer                *helper.NatsContainer
	userServiceContainer         *helper.UserServiceContainer
	fileServiceContainer         *helper.FileServiceContainer
	notificationServiceContainer *helper.NotificationServiceContainer
	mailHogContainer             *helper.MailhogContainer
}

func (r *ResetPasswordITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for ResetPasswordITSuite")
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

	fContainer, err := helper.StartFileServiceContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	r.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := helper.StartUserServiceContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	r.userServiceContainer = uContainer

	noContainer, err := helper.StartNotificationServiceContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting notification service container: %s", err)
	}
	r.notificationServiceContainer = noContainer

	mailContainer, err := helper.StartMailhogContainer(r.ctx, r.network.Name)
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	r.mailHogContainer = mailContainer

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (r *ResetPasswordITSuite) TearDownSuite() {
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
	if err := r.notificationServiceContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating notification service container: %s", err)
	}
	if err := r.mailHogContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating mailhog container: %s", err)
	}

	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for ResetPasswordITSuite")
}
func TestResetPasswordITSuite(t *testing.T) {
	suite.Run(t, &ResetPasswordITSuite{})
}
func (r *ResetPasswordITSuite) TestResetPasswordIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, r.T())

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusCreated, response.StatusCode)
	r.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()

	// verify email
	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", r.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	r.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	r.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusOK, verifyResponse.StatusCode)
	r.Contains(string(verifyBody), "Verification Success")

	// reset password

	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8181/reset-password", body)
	r.NoError(err)

	resetResponse, err := client.Do(resetRequest)
	r.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusOK, resetResponse.StatusCode)
	r.Contains(string(resetBody), "Reset password email has been sent")

	// check email
	regex = `http://localhost:8181/change-password\?userid=[^&]+&resetPasswordToken=[^"']+`
	resetLink := helper.RetrieveDataFromEmail(email, regex, "mail", r.T())
	r.NotEmpty(resetLink)
}

func (r *ResetPasswordITSuite) TestResetPasswordIT_MissinBody() {
	body := &bytes.Buffer{}

	encoder := gin.H{}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8181/reset-password", body)
	r.NoError(err)

	client := http.Client{}
	resetResponse, err := client.Do(resetRequest)
	r.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, resetResponse.StatusCode)
	r.Contains(string(resetBody), "missing email")
}

func (r *ResetPasswordITSuite) TestResetPasswordIT_NotVerified() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, r.T())

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusCreated, response.StatusCode)
	r.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()

	// reset password
	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8181/reset-password", body)
	r.NoError(err)

	resetResponse, err := client.Do(resetRequest)
	r.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusUnauthorized, resetResponse.StatusCode)
	r.Contains(string(resetBody), "user is not verified")
}

func (r *ResetPasswordITSuite) TestResetPasswordIT_NotFound() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8181/reset-password", body)
	r.NoError(err)

	client := http.Client{}
	resetResponse, err := client.Do(resetRequest)
	r.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusNotFound, resetResponse.StatusCode)
	r.Contains(string(resetBody), "user not found")
}
