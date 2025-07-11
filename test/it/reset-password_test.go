package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/dropboks/auth-service/test/helper"
	_helper "github.com/dropboks/sharedlib/test/helper"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type ResetPasswordITSuite struct {
	suite.Suite
	ctx context.Context

	network                      *testcontainers.DockerNetwork
	userPgContainer              *_helper.PostgresContainer
	authPgContainer              *_helper.PostgresContainer
	redisContainer               *_helper.RedisContainer
	minioContainer               *_helper.MinioContainer
	natsContainer                *_helper.NatsContainer
	authContainer                *_helper.AuthServiceContainer
	userServiceContainer         *_helper.UserServiceContainer
	fileServiceContainer         *_helper.FileServiceContainer
	notificationServiceContainer *_helper.NotificationServiceContainer
	mailHogContainer             *_helper.MailhogContainer
}

func (r *ResetPasswordITSuite) SetupSuite() {
	log.Println("Setting up integration test suite for ResetPasswordITSuite")
	r.ctx = context.Background()

	viper.SetConfigName("config.test")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}

	// spawn sharedNetwork
	r.network = _helper.StartNetwork(r.ctx)

	// spawn user db
	userPgContainer, err := _helper.StartPostgresContainer(r.ctx, r.network.Name, "user_db", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	r.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartPostgresContainer(r.ctx, r.network.Name, "auth_db", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	r.authPgContainer = authPgContainer

	// spawn redis
	rContainer, err := _helper.StartRedisContainer(r.ctx, r.network.Name, viper.GetString("container.redis_version"))
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	r.redisContainer = rContainer

	mContainer, err := _helper.StartMinioContainer(r.ctx, r.network.Name, viper.GetString("container.minio_version"))
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	r.minioContainer = mContainer

	// spawn nats
	nContainer, err := _helper.StartNatsContainer(r.ctx, r.network.Name, viper.GetString("container.nats_version"))
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	r.natsContainer = nContainer

	aContainer, err := _helper.StartAuthServiceContainer(r.ctx, r.network.Name, viper.GetString("container.auth_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting auth service container: %s", err)
	}
	r.authContainer = aContainer

	fContainer, err := _helper.StartFileServiceContainer(r.ctx, r.network.Name, viper.GetString("container.file_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	r.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := _helper.StartUserServiceContainer(r.ctx, r.network.Name, viper.GetString("container.user_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	r.userServiceContainer = uContainer

	noContainer, err := _helper.StartNotificationServiceContainer(r.ctx, r.network.Name, viper.GetString("container.notification_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting notification service container: %s", err)
	}
	r.notificationServiceContainer = noContainer

	mailContainer, err := _helper.StartMailhogContainer(r.ctx, r.network.Name, viper.GetString("container.mailhog_version"))
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	r.mailHogContainer = mailContainer

}
func (r *ResetPasswordITSuite) TearDownSuite() {
	if err := r.userPgContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating user postgres container: %s", err)
	}
	if err := r.authPgContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating auth postgres container: %s", err)
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
	if err := r.authContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating auth service container: %s", err)
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

	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	regex := `http://localhost:8081/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", r.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	r.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	r.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusOK, verifyResponse.StatusCode)
	r.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// reset password
	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8081/reset-password", body)
	r.NoError(err)

	resetResponse, err := client.Do(resetRequest)
	r.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusOK, resetResponse.StatusCode)
	r.Contains(string(resetBody), "Reset password email has been sent")

	// check email
	regex = `http://localhost:8081/change-password\?userid=[^&]+&resetPasswordToken=[^"']+`
	resetLink := helper.RetrieveDataFromEmail(email, regex, "mail", r.T())
	r.NotEmpty(resetLink)
}

func (r *ResetPasswordITSuite) TestResetPasswordIT_MissinBody() {
	body := &bytes.Buffer{}

	encoder := gin.H{}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8081/reset-password", body)
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

	time.Sleep(time.Second) //give a time for auth_db update the user

	// reset password
	body := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(body).Encode(encoder)

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8081/reset-password", body)
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

	resetRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8081/reset-password", body)
	r.NoError(err)

	client := http.Client{}
	resetResponse, err := client.Do(resetRequest)
	r.NoError(err)

	resetBody, err := io.ReadAll(resetResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusNotFound, resetResponse.StatusCode)
	r.Contains(string(resetBody), "user not found")
}
