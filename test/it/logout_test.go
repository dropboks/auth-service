package service_test

import (
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
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type LogoutITSuite struct {
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

func (l *LogoutITSuite) SetupSuite() {

	log.Println("Setting up integration test suite for LogoutITSuite")
	l.ctx = context.Background()

	viper.SetConfigName("config.test")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}

	// spawn sharedNetwork
	l.network = _helper.StartNetwork(l.ctx)

	// spawn user db
	userPgContainer, err := _helper.StartPostgresContainer(l.ctx, l.network.Name, "user_db", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	l.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartPostgresContainer(l.ctx, l.network.Name, "auth_db", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	l.authPgContainer = authPgContainer

	// spawn redis
	rContainer, err := _helper.StartRedisContainer(l.ctx, l.network.Name, viper.GetString("container.redis_version"))
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	l.redisContainer = rContainer

	mContainer, err := _helper.StartMinioContainer(l.ctx, l.network.Name, viper.GetString("container.minio_version"))
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	l.minioContainer = mContainer

	// spawn nats
	nContainer, err := _helper.StartNatsContainer(l.ctx, l.network.Name, viper.GetString("container.nats_version"))
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	l.natsContainer = nContainer

	aContainer, err := _helper.StartAuthServiceContainer(l.ctx, l.network.Name, viper.GetString("container.auth_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting auth service container: %s", err)
	}
	l.authContainer = aContainer

	fContainer, err := _helper.StartFileServiceContainer(l.ctx, l.network.Name, viper.GetString("container.file_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	l.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := _helper.StartUserServiceContainer(l.ctx, l.network.Name, viper.GetString("container.user_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	l.userServiceContainer = uContainer

	noContainer, err := _helper.StartNotificationServiceContainer(l.ctx, l.network.Name, viper.GetString("container.notification_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting notification service container: %s", err)
	}
	l.notificationServiceContainer = noContainer

	mailContainer, err := _helper.StartMailhogContainer(l.ctx, l.network.Name, viper.GetString("container.mailhog_version"))
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	l.mailHogContainer = mailContainer

}
func (l *LogoutITSuite) TearDownSuite() {
	if err := l.userPgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating user postgres container: %s", err)
	}
	if err := l.authPgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating auth postgres container: %s", err)
	}
	if err := l.redisContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := l.minioContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := l.natsContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := l.authContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating auth service container: %s", err)
	}
	if err := l.userServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := l.fileServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}
	if err := l.notificationServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating notification service container: %s", err)
	}
	if err := l.mailHogContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating mailhog container: %s", err)
	}

	log.Println("Tear Down integration test suite for LogoutITSuite")
}
func TestLogoutITSuite(t *testing.T) {
	suite.Run(t, &LogoutITSuite{})
}

func (l *LogoutITSuite) TestLogoutIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, l.T())

	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	l.NoError(err)

	l.Equal(http.StatusCreated, response.StatusCode)
	l.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()

	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	regex := `http://localhost:8081/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", l.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	l.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	l.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	l.NoError(err)

	l.Equal(http.StatusOK, verifyResponse.StatusCode)
	l.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "Login Success")

	var respData map[string]interface{}
	err = json.Unmarshal(byteBody, &respData)
	l.NoError(err)

	jwt, ok := respData["data"].(string)
	l.True(ok, "expected jwt token in data field")

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/logout", nil)
	l.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	l.NoError(err)
	defer verifyResp.Body.Close()

	l.Equal(http.StatusNoContent, verifyResp.StatusCode)
}

func (l *LogoutITSuite) TestLogoutIT_MissingToken() {

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/logout", nil)
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

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/logout", nil)
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

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/logout", nil)
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
