package service_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/dropboks/auth-service/test/helper"
	_helper "github.com/dropboks/sharedlib/test/helper"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type RegisterITSuite struct {
	suite.Suite
	ctx context.Context

	network              *testcontainers.DockerNetwork
	userPgContainer      *_helper.PostgresContainer
	authPgContainer      *_helper.PostgresContainer
	redisContainer       *_helper.RedisContainer
	minioContainer       *_helper.MinioContainer
	natsContainer        *_helper.NatsContainer
	authContainer        *_helper.AuthServiceContainer
	userServiceContainer *_helper.UserServiceContainer
	fileServiceContainer *_helper.FileServiceContainer
}

func (r *RegisterITSuite) SetupSuite() {
	exec.Command("docker", "rm", "-f", "user_db").Run()
	exec.Command("docker", "rm", "-f", "auth_db").Run()
	log.Println("Setting up integration test suite for RegisterITSuite")
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
}
func (r *RegisterITSuite) TearDownSuite() {
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

	log.Println("Tear Down integration test suite for RegisterITSuite")
}
func TestRegisterITSuite(t *testing.T) {
	suite.Run(t, &RegisterITSuite{})
}

func (r *RegisterITSuite) TestRegisterIT_Success() {
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
}

func (r *RegisterITSuite) TestRegisterIT_MissingBody() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8081/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "invalid input")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_EmailAlreadyExist() {
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

	time.Sleep(time.Second)

	secRequest := helper.Register(email, r.T())

	client = http.Client{}
	secResponse, err := client.Do(secRequest)
	r.NoError(err)

	secByteBody, err := io.ReadAll(secResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusConflict, secResponse.StatusCode)
	r.Contains(string(secByteBody), "user with this email exist")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_WrongExtension() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test2@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.webp")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8081/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "error file extension, support jpg, jpeg, and png")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_LimitSizeExceeded() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test3@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")
	fileWriter, _ := formWriter.CreateFormFile("image", "test.png")
	largeData := make([]byte, 8*1024*1024)
	_, err := fileWriter.Write(largeData)
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8081/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "max size exceeded: 6mb")
	response.Body.Close()
}

func (r *RegisterITSuite) TestRegisterIT_PasswordAndConfirmPasswordDoesntMatch() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test4@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password1234")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8081/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "password and confirm password doesn't match")
	response.Body.Close()
}
