package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
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

type ChangePasswordITSuite struct {
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

func (c *ChangePasswordITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for ChangePasswordITSuite")
	c.ctx = context.Background()
	gin.SetMode(gin.TestMode)
	os.Setenv("ENV", "test")
	env.Load()

	// spawn sharedNetwork
	c.network = helper.StartNetwork(c.ctx)

	// spawn posgresql
	pgContainer, err := helper.StartPostgresContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	c.pgContainer = pgContainer

	// spawn redis
	rContainer, err := helper.StartRedisContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	c.redisContainer = rContainer

	mContainer, err := helper.StartMinioContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	c.minioContainer = mContainer

	// spawn nats
	nContainer, err := helper.StartNatsContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	c.natsContainer = nContainer

	fContainer, err := helper.StartFileServiceContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	c.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := helper.StartUserServiceContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	c.userServiceContainer = uContainer

	noContainer, err := helper.StartNotificationServiceContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting notification service container: %s", err)
	}
	c.notificationServiceContainer = noContainer

	mailContainer, err := helper.StartMailhogContainer(c.ctx, c.network.Name)
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	c.mailHogContainer = mailContainer

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (c *ChangePasswordITSuite) TearDownSuite() {
	if err := c.pgContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
	if err := c.redisContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := c.minioContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := c.natsContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := c.userServiceContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := c.fileServiceContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}
	if err := c.notificationServiceContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating notification service container: %s", err)
	}
	if err := c.mailHogContainer.Terminate(c.ctx); err != nil {
		log.Fatalf("error terminating mailhog container: %s", err)
	}

	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for ChangePasswordITSuite")
}
func TestChangePasswordITSuite(t *testing.T) {
	suite.Run(t, &ChangePasswordITSuite{})
}

func (c *ChangePasswordITSuite) TestChangePasswordIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, c.T())

	client := http.Client{}
	response, err := client.Do(request)
	c.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	c.NoError(err)

	c.Equal(http.StatusCreated, response.StatusCode)
	c.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()

	// verify email
	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", c.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	c.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	c.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusOK, verifyResponse.StatusCode)
	c.Contains(string(verifyBody), "Verification Success")

	// reset password

	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8181/reset-password", body)
	c.NoError(err)

	resetResponse, err := client.Do(resetRequest)
	c.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusOK, resetResponse.StatusCode)
	c.Contains(string(resetBody), "Reset password email has been sent")

	// check email
	regex = `http://localhost:8181/change-password\?userid=[^&]+&resetPasswordToken=[^"']+`
	resetLink := helper.RetrieveDataFromEmail(email, regex, "mail", c.T())
	c.NotEmpty(resetLink)

	// change passsword
	body = &bytes.Buffer{}

	encoder = gin.H{
		"password":         "password12345",
		"confirm_password": "password12345",
	}
	_ = json.NewEncoder(body).Encode(encoder)
	changePasswordReq, err := http.NewRequest(http.MethodPatch, resetLink, body)
	c.NoError(err)

	changeResponse, err := client.Do(changePasswordReq)
	c.NoError(err)

	changeBody, err := io.ReadAll(changeResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusOK, changeResponse.StatusCode)
	c.Contains(string(changeBody), "password changed")
}

func (c *ChangePasswordITSuite) TestChangePasswordIT_MissingQuery() {

	body := &bytes.Buffer{}

	encoder := gin.H{
		"password":         "password12345",
		"confirm_password": "password12345",
	}
	_ = json.NewEncoder(body).Encode(encoder)
	changePasswordReq, err := http.NewRequest(http.MethodPatch, `http://localhost:8181/change-password?`, body)
	c.NoError(err)

	client := http.Client{}
	changeResponse, err := client.Do(changePasswordReq)
	c.NoError(err)

	changeBody, err := io.ReadAll(changeResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusBadRequest, changeResponse.StatusCode)
	c.Contains(string(changeBody), "invalid input")
}
func (c *ChangePasswordITSuite) TestChangePasswordIT_MissingBody() {

	body := &bytes.Buffer{}

	encoder := gin.H{
		"password": "password12345",
	}
	_ = json.NewEncoder(body).Encode(encoder)
	changePasswordReq, err := http.NewRequest(http.MethodPatch, `http://localhost:8181/change-password?userid=valid-user-id&resetPasswordToken=valid-reset-password-token`, body)
	c.NoError(err)

	client := http.Client{}
	changeResponse, err := client.Do(changePasswordReq)
	c.NoError(err)

	changeBody, err := io.ReadAll(changeResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusBadRequest, changeResponse.StatusCode)
	c.Contains(string(changeBody), "invalid input")
}

func (c *ChangePasswordITSuite) TestChangePasswordIT_InvalidToken() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, c.T())

	client := http.Client{}
	response, err := client.Do(request)
	c.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	c.NoError(err)

	c.Equal(http.StatusCreated, response.StatusCode)
	c.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()

	// verify email
	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", c.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	c.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	c.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusOK, verifyResponse.StatusCode)
	c.Contains(string(verifyBody), "Verification Success")

	// reset password

	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8181/reset-password", body)
	c.NoError(err)

	resetResponse, err := client.Do(resetRequest)
	c.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusOK, resetResponse.StatusCode)
	c.Contains(string(resetBody), "Reset password email has been sent")

	// check email
	regex = `http://localhost:8181/change-password\?userid=[^&]+&resetPasswordToken=[^"']+`
	resetLink := helper.RetrieveDataFromEmail(email, regex, "mail", c.T())
	c.NotEmpty(resetLink)

	invalidToken := "invalid" + fmt.Sprintf("%d", rand.Intn(1000000))

	re := regexp.MustCompile(`(resetPasswordToken=)[^"']+`)
	invalidResetLink := re.ReplaceAllString(resetLink, "${1}"+invalidToken)

	// change passsword
	body = &bytes.Buffer{}

	encoder = gin.H{
		"password":         "password12345",
		"confirm_password": "password12345",
	}
	_ = json.NewEncoder(body).Encode(encoder)
	changePasswordReq, err := http.NewRequest(http.MethodPatch, invalidResetLink, body)
	c.NoError(err)

	changeResponse, err := client.Do(changePasswordReq)
	c.NoError(err)

	changeBody, err := io.ReadAll(changeResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusUnauthorized, changeResponse.StatusCode)
	c.Contains(string(changeBody), "invalid token")
}

func (c *ChangePasswordITSuite) TestChangePasswordIT_NotFound() {
	body := &bytes.Buffer{}

	encoder := gin.H{
		"password":         "password12345",
		"confirm_password": "password12345",
	}
	_ = json.NewEncoder(body).Encode(encoder)
	changePasswordReq, err := http.NewRequest(http.MethodPatch, "http://localhost:8181/change-password?userid=invalid-userid&resetPasswordToken=valid-token", body)
	c.NoError(err)

	client := http.Client{}
	changeResponse, err := client.Do(changePasswordReq)
	c.NoError(err)

	changeBody, err := io.ReadAll(changeResponse.Body)
	c.NoError(err)

	c.Equal(http.StatusNotFound, changeResponse.StatusCode)
	c.Contains(string(changeBody), "user not found")
}
