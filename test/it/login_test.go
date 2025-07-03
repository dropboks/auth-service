package service_test

import (
	"context"
	"log"
	"os"
	"syscall"
	"testing"

	"github.com/dropboks/auth-service/cmd/bootstrap"
	"github.com/dropboks/auth-service/cmd/server"
	"github.com/dropboks/auth-service/config/env"
	"github.com/dropboks/auth-service/test/helper"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
)

type LoginITSuite struct {
	suite.Suite
	ctx                  context.Context
	pgContainer          *helper.PostgresContainer
	redisContainer       *helper.RedisContainer
	minioContainer       *helper.MinioContainer
	natsContainer        *helper.NatsContainer
	userServiceContainer *helper.UserServiceContainer
	fileServiceContainer *helper.FileServiceContainer
}

func (l *LoginITSuite) SetupSuite() {
	log.Println("Setting up integration test suite for LoginITSuite")
	l.ctx = context.Background()
	gin.SetMode(gin.TestMode)
	os.Setenv("ENV", "test")
	env.Load()
	// spawn posgresql
	pgContainer, err := helper.StartPostgresContainer(l.ctx)
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	l.pgContainer = pgContainer

	// spawn redis
	rContainer, err := helper.StartRedisContainer(l.ctx)
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	l.redisContainer = rContainer

	// spawn minio
	mContainer, err := helper.StartMinioContainer(l.ctx)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	l.minioContainer = mContainer

	// spawn nats
	nContainer, err := helper.StartNatsContainer(l.ctx)
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	l.natsContainer = nContainer

	// spawn user service
	uContainer, err := helper.StartUserServiceContainer(l.ctx)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting user service container: %s", err)
	}
	l.userServiceContainer = uContainer

	// spawn file service
	fContainer, err := helper.StartFileServiceContainer(l.ctx)
	if err != nil {
		log.Println("make sure the image is exist")
		log.Fatalf("failed starting file service container: %s", err)
	}
	l.fileServiceContainer = fContainer

	container := bootstrap.Run()
	serverReady := make(chan bool)
	server := &server.Server{
		Container:   container,
		ServerReady: serverReady,
	}
	go server.Run()
	<-serverReady
}
func (l *LoginITSuite) TearDownSuite() {
	if err := l.pgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
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

	p, _ := os.FindProcess(syscall.Getpid())
	_ = p.Signal(syscall.SIGINT)
	log.Println("Tear Down integration test suite for LoginITSuite")
}

func (l *LoginITSuite) SetupTest() {
	
}

func TestChangePasswordHandlerSuite(t *testing.T) {
	suite.Run(t, &LoginITSuite{})
}

func (l *LoginITSuite) TestLoginIT_Success() {}
