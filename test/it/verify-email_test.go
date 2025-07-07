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
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/dropboks/auth-service/cmd/bootstrap"
	"github.com/dropboks/auth-service/cmd/server"
	c "github.com/dropboks/auth-service/config/cache"
	"github.com/dropboks/auth-service/config/env"
	"github.com/dropboks/auth-service/internal/infrastructure/cache"
	"github.com/dropboks/auth-service/test/helper"
	"github.com/dropboks/sharedlib/utils"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type VerifyEmailITSuite struct {
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

func (v *VerifyEmailITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "db").Run()
	log.Println("Setting up integration test suite for VerifyEmailITSuite")
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

	// spawn minio
	mContainer, err := helper.StartMinioContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	v.minioContainer = mContainer

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

	// spawn file service
	fContainer, err := helper.StartFileServiceContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	v.fileServiceContainer = fContainer

	// spawn notification service
	noContainer, err := helper.StartNotificationServiceContainer(v.ctx, v.network.Name)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting notification service container: %s", err)
	}
	v.notificationServiceContainer = noContainer

	mailContainer, err := helper.StartMailhogContainer(v.ctx, v.network.Name)
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

func (v *VerifyEmailITSuite) TearDownSuite() {
	if err := v.pgContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
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
	log.Println("Tear Down integration test suite for VerifyEmailITSuite")
}
func TestVerifyEmailITSuite(t *testing.T) {
	suite.Run(t, &VerifyEmailITSuite{})
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	// verify email
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_MissingQUery() {

	client := http.Client{}
	verifyRequest, err := http.NewRequest(http.MethodGet, "http://localhost:8181/verify-email?", nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusBadRequest, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "invalid input")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_TokenInvalid() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	// get the first link
	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	// resend verification
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	resendVerification, err := http.NewRequest(http.MethodPost, "http://localhost:8181/resend-verification-email", reqBody)
	v.NoError(err)

	resendVerificationResponse, err := client.Do(resendVerification)

	v.NoError(err)
	resendVerificationResponseBody, err := io.ReadAll(resendVerificationResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(resendVerificationResponseBody), "Check your email for verification")

	// request with link
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusUnauthorized, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "token is invalid")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_AlreadyVerified() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	// verify email
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")

	secondVerifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	secondVerifyResponse, err := client.Do(secondVerifyRequest)
	v.NoError(err)

	secondVerifyBody, err := io.ReadAll(secondVerifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusConflict, secondVerifyResponse.StatusCode)
	v.Contains(string(secondVerifyBody), "user is already verified")

}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_KeyNotFound() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	useridRe := regexp.MustCompile(`userid=([^&]+)`)
	matches := useridRe.FindStringSubmatch(link)
	v.True(len(matches) > 1, "userid not found in link")
	userid := matches[1]
	log.Println("Extracted userid:", userid)

	logg := zerolog.Nop()
	red, err := c.New(logg)
	v.NoError(err)
	redCache := cache.New(red, logg)

	key := fmt.Sprintf("verificationToken:%s", userid)
	err = redCache.Delete(v.ctx, key)
	v.NoError(err)

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusNotFound, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "verification token is not found")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_UserNotFound() {
	link := "http://localhost:8181/verify-email?userid=examplerandom&token=random-token-that-is-not-valid"
	client := http.Client{}
	re := regexp.MustCompile(`userid=([^&]+)`)
	randomUserID := fmt.Sprintf("random-%d", time.Now().UnixNano())
	modifiedLink := re.ReplaceAllString(link, fmt.Sprintf("userid=%s", randomUserID))

	verifyRequest, err := http.NewRequest(http.MethodGet, modifiedLink, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusNotFound, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "user not found")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_ChangeTokenSuccess() {
	// - register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	regex := `http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	// - verify-email
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")

	// - login
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    email,
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	v.NoError(err)

	response, err := client.Do(req)
	v.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, response.StatusCode)
	v.Contains(string(byteBody), "Login Success")

	// - verify
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

	// get the response header user data -> pass to update email header in
	// userDataHeader := c.Request.Header.Get("User-Data")
	// UserId string `json:"user_id"`
	userDataHeader := verifyResp.Header.Get("User-Data")
	v.NotEmpty(userDataHeader, "User-Data header should not be empty")

	var ud utils.UserData
	err = json.Unmarshal([]byte(userDataHeader), &ud)
	v.NoError(err)
	v.NotEmpty(ud.UserId, "user_id should not be empty")

	// update email
	newEmail := fmt.Sprintf("test+updated+%d@example.com", time.Now().UnixNano())
	updateBody := &bytes.Buffer{}
	updatePayload := gin.H{
		"email": newEmail,
	}
	_ = json.NewEncoder(updateBody).Encode(updatePayload)

	// - update email in the user endpoint
	updateReq, err := http.NewRequest(http.MethodPatch, "http://localhost:8182/email", updateBody)
	v.NoError(err)
	updateReq.Header.Set("User-Data", userDataHeader)
	updateResp, err := client.Do(updateReq)
	v.NoError(err)
	updateRespBody, err := io.ReadAll(updateResp.Body)
	v.NoError(err)
	v.Equal(http.StatusOK, updateResp.StatusCode)
	v.Contains(string(updateRespBody), "verify to change email")

	// get the link from email in mailhog
	regex = `http://localhost:8181/verify-email\?userid=[^&]+&changeEmailToken=[^"']+`
	link = helper.RetrieveDataFromEmail(newEmail, regex, "mail", v.T())
	// verify new email
	verifyRequest, err = http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)
	verifyResponse, err = client.Do(verifyRequest)
	v.NoError(err)
	verifyBody, err = io.ReadAll(verifyResponse.Body)
	v.NoError(err)
	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")
}
