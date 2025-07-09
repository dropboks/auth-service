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
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/dropboks/auth-service/cmd/bootstrap"
	"github.com/dropboks/auth-service/cmd/server"
	"github.com/dropboks/auth-service/config/env"
	"github.com/dropboks/auth-service/pkg/generators"
	"github.com/spf13/viper"

	"github.com/dropboks/auth-service/test/helper"
	_helper "github.com/dropboks/sharedlib/test/helper"
	"github.com/dropboks/sharedlib/utils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type VerifyOTPITSuite struct {
	suite.Suite
	ctx context.Context

	network                      *testcontainers.DockerNetwork
	userPgContainer              *_helper.PostgresContainer
	authPgContainer              *_helper.PostgresContainer
	redisContainer               *_helper.RedisContainer
	minioContainer               *_helper.MinioContainer
	natsContainer                *_helper.NatsContainer
	userServiceContainer         *_helper.UserServiceContainer
	fileServiceContainer         *_helper.FileServiceContainer
	notificationServiceContainer *_helper.NotificationServiceContainer
	mailHogContainer             *_helper.MailhogContainer
}

func (v *VerifyOTPITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "user_db").Run()
	exec.Command("docker", "rm", "-f", "auth_db").Run()

	log.Println("Setting up integration test suite for VerifyOTPITSuite")
	v.ctx = context.Background()
	gin.SetMode(gin.TestMode)
	os.Setenv("ENV", "test")
	env.Load()

	// spawn sharedNetwork
	v.network = _helper.StartNetwork(v.ctx)

	// spawn user db
	userPgContainer, err := _helper.StartPostgresContainer(v.ctx, v.network.Name, "user_db", "5432", viper.GetString("container.postgresql_version"))
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	v.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartPostgresContainer(v.ctx, v.network.Name, "auth_db", "5433", viper.GetString("container.postgresql_version"))
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

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (v *VerifyOTPITSuite) TearDownSuite() {
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

	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for VerifyOTPITSuite")
}
func TestVerifyOTPITSuite(t *testing.T) {
	suite.Run(t, &VerifyOTPITSuite{})
}

func (v *VerifyOTPITSuite) TestVerifyOTPIT_Success() {
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
	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
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

	// verify token
	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	v.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)
	defer verifyResp.Body.Close()

	v.Equal(http.StatusNoContent, verifyResp.StatusCode)
	userDataHeader := verifyResp.Header.Get("User-Data")
	v.NotEmpty(userDataHeader, "User-Data header should not be empty")

	var ud utils.UserData
	err = json.Unmarshal([]byte(userDataHeader), &ud)
	v.NoError(err)
	v.NotEmpty(ud.UserId, "user_id should not be empty")

	// updateuser enable 2FA
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("two_factor_enabled", "true")
	formWriter.Close()

	request, err = http.NewRequest(http.MethodPatch, "http://localhost:8182/", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	request.Header.Set("User-Data", userDataHeader)

	v.NoError(err)

	client = http.Client{}
	response, err = client.Do(request)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusOK, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "success update profile data")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, v.T())

	client = http.Client{}
	response, err = client.Do(request)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusOK, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "OTP Has been sent to linked email")

	// check email for otp
	regex = `<div class="otp">\s*([0-9]{4,8})\s*</div>`
	otp := helper.RetrieveDataFromEmail(email, regex, "otp", v.T())
	v.NotEmpty(otp)

	// verify otp
	reqBody = &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
		"otp":   otp,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify-otp", reqBody)
	v.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusOK, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "OTP is Valid")
}

func (v *VerifyOTPITSuite) TestVerifyOTPIT_MissingBody() {
	// verify otp
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify-otp", reqBody)
	v.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	v.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	v.Equal(http.StatusBadRequest, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "invalid input")
}

func (v *VerifyOTPITSuite) TestVerifyOTPIT_InvalidOTP() {
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
	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
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

	// verify token
	verifyReq, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify", nil)
	v.NoError(err)
	verifyReq.Header.Set("Authorization", "Bearer "+jwt)

	verifyResp, err := client.Do(verifyReq)
	v.NoError(err)
	defer verifyResp.Body.Close()

	v.Equal(http.StatusNoContent, verifyResp.StatusCode)
	userDataHeader := verifyResp.Header.Get("User-Data")
	v.NotEmpty(userDataHeader, "User-Data header should not be empty")

	var ud utils.UserData
	err = json.Unmarshal([]byte(userDataHeader), &ud)
	v.NoError(err)
	v.NotEmpty(ud.UserId, "user_id should not be empty")

	// updateuser enable 2FA
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("two_factor_enabled", "true")
	formWriter.Close()

	request, err = http.NewRequest(http.MethodPatch, "http://localhost:8182/", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	request.Header.Set("User-Data", userDataHeader)

	v.NoError(err)

	client = http.Client{}
	response, err = client.Do(request)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusOK, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "success update profile data")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, v.T())

	client = http.Client{}
	response, err = client.Do(request)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusOK, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "OTP Has been sent to linked email")

	// check email for otp
	regex = `<div class="otp">\s*([0-9]{4,8})\s*</div>`
	otp := helper.RetrieveDataFromEmail(email, regex, "otp", v.T())
	v.NotEmpty(otp)

	// verify otp
	reqBody = &bytes.Buffer{}

	otpValue, _ := generators.NewRandomStringGenerator().GenerateOTP()
	encoder := gin.H{
		"email": email,
		"otp":   otpValue,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify-otp", reqBody)
	v.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusUnauthorized, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "OTP is invalid")
}

func (v *VerifyOTPITSuite) TestVerifyOTPIT_KeyNotFound() {
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

	// verify otp
	reqBody := &bytes.Buffer{}

	otpValue, _ := generators.NewRandomStringGenerator().GenerateOTP()
	encoder := gin.H{
		"email": email,
		"otp":   otpValue,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify-otp", reqBody)
	v.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	v.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	v.Equal(http.StatusNotFound, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "otp is invalid")
}

func (v *VerifyOTPITSuite) TestVerifyOTPIT_UserNotFound() {

	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	// verify otp
	reqBody := &bytes.Buffer{}

	otpValue, _ := generators.NewRandomStringGenerator().GenerateOTP()
	encoder := gin.H{
		"email": email,
		"otp":   otpValue,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/verify-otp", reqBody)
	v.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	v.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	v.Equal(http.StatusNotFound, response.StatusCode)
	v.NoError(err)
	v.Contains(string(byteBody), "user not found")
}
