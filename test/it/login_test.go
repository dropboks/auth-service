package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/dropboks/auth-service/test/helper"
	_helper "github.com/dropboks/sharedlib/test/helper"
	"github.com/dropboks/sharedlib/utils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type LoginITSuite struct {
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

func (l *LoginITSuite) SetupSuite() {

	log.Println("Setting up integration test suite for LoginITSuite")
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

func (l *LoginITSuite) TearDownSuite() {
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
	log.Println("Tear Down integration test suite for LoginITSuite")
}
func TestLoginITSuite(t *testing.T) {
	suite.Run(t, &LoginITSuite{})
}

func (l *LoginITSuite) TestLoginIT_Success() {
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
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_Success2FA() {

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

	// verify token
	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8081/verify", nil)
	l.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	l.NoError(err)
	defer verifyResp.Body.Close()

	l.Equal(http.StatusNoContent, verifyResp.StatusCode)
	userDataHeader := verifyResp.Header.Get("User-Data")
	l.NotEmpty(userDataHeader, "User-Data header should not be empty")

	var ud utils.UserData
	err = json.Unmarshal([]byte(userDataHeader), &ud)
	l.NoError(err)
	l.NotEmpty(ud.UserId, "user_id should not be empty")

	// updateuser enable 2FA
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("two_factor_enabled", "true")
	formWriter.Close()

	request, err = http.NewRequest(http.MethodPatch, "http://localhost:8082/", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	request.Header.Set("User-Data", userDataHeader)

	l.NoError(err)

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "success update profile data")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "OTP Has been sent to linked email")

	// check email for otp
	regex = `<div class="otp">\s*([0-9]{4,8})\s*</div>`
	otp := helper.RetrieveDataFromEmail(email, regex, "otp", l.T())
	l.NotEmpty(otp)

	// verify otp
	reqBody = &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
		"otp":   otp,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8081/verify-otp", reqBody)
	l.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "OTP is Valid")
}

func (l *LoginITSuite) TestLoginIT_MissingBody() {

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": "test2@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8081/login", reqBody)
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

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusUnauthorized, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "user is not verified")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_PasswordDoesntMatch() {
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
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    email,
		"password": "password1234",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8081/login", reqBody)
	l.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusUnauthorized, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "email or password is wrong")
	response.Body.Close()
}

func (l *LoginITSuite) TestLoginIT_UserNotfound() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Login(email, l.T())
	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusNotFound, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "user not found")
	response.Body.Close()
}
