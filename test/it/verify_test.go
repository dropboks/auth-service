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

type VerifyITSuite struct {
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

func (v *VerifyITSuite) SetupSuite() {
	log.Println("Setting up integration test suite for VerifyITSuite")
	v.ctx = context.Background()

	viper.SetConfigName("config.test")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}

	// spawn sharedNetwork
	v.network = _helper.StartNetwork(v.ctx)

	// spawn user db
	userPgContainer, err := _helper.StartPostgresContainer(v.ctx, v.network.Name, "user_db", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	v.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartPostgresContainer(v.ctx, v.network.Name, "auth_db", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	v.authPgContainer = authPgContainer

	// spawn redis
	rContainer, err := _helper.StartRedisContainer(v.ctx, v.network.Name, viper.GetString("container.redis_version"))
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	v.redisContainer = rContainer

	mContainer, err := _helper.StartMinioContainer(v.ctx, v.network.Name, viper.GetString("container.minio_version"))
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	v.minioContainer = mContainer

	// spawn nats
	nContainer, err := _helper.StartNatsContainer(v.ctx, v.network.Name, viper.GetString("container.nats_version"))
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	v.natsContainer = nContainer

	fContainer, err := _helper.StartFileServiceContainer(v.ctx, v.network.Name, viper.GetString("container.file_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	v.fileServiceContainer = fContainer

	aContainer, err := _helper.StartAuthServiceContainer(v.ctx, v.network.Name, viper.GetString("container.auth_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting auth service container: %s", err)
	}
	v.authContainer = aContainer
	// spawn user service
	uContainer, err := _helper.StartUserServiceContainer(v.ctx, v.network.Name, viper.GetString("container.user_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	v.userServiceContainer = uContainer

	noContainer, err := _helper.StartNotificationServiceContainer(v.ctx, v.network.Name, viper.GetString("container.notification_service_version"))
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting notification service container: %s", err)
	}
	v.notificationServiceContainer = noContainer

	mailContainer, err := _helper.StartMailhogContainer(v.ctx, v.network.Name, viper.GetString("container.mailhog_version"))
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	v.mailHogContainer = mailContainer

}
func (v *VerifyITSuite) TearDownSuite() {
	if err := v.userPgContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating user postgres container: %s", err)
	}
	if err := v.authPgContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating auth postgres container: %s", err)
	}
	if err := v.redisContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := v.minioContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := v.natsContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := v.authContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating auth service container: %s", err)
	}
	if err := v.userServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := v.fileServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}
	if err := v.notificationServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating notification service container: %s", err)
	}
	if err := v.mailHogContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating mailhog container: %s", err)
	}

	log.Println("Tear Down integration test suite for VerifyITSuite")
}
func TestVerifyITSuite(t *testing.T) {
	suite.Run(t, &VerifyITSuite{})
}

func (v *VerifyITSuite) TestVerifyIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, v.T())

	client := http.Client{}
	response, err := client.Do(request)
	v.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, response.StatusCode)
	v.Contains(string(byteBody), "Register Success. Check your email for verification.")
	response.Body.Close()

	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	regex := `http://localhost:8081/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, v.T())

	client = http.Client{}
	response, err = client.Do(request)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusOK, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "Login Success")

	var respData map[string]interface{}
	err = json.Unmarshal(byteBody, &respData)
	v.NoError(err)

	jwt, ok := respData["data"].(string)
	v.True(ok, "expected jwt token in data field")

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/verify", nil)
	v.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)
	defer verifyResp.Body.Close()

	v.Equal(http.StatusNoContent, verifyResp.StatusCode)
}

func (v *VerifyITSuite) TestVerifyIT_MissingToken() {

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/verify", nil)
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

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/verify", nil)
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

	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/verify", nil)
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
