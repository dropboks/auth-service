package repository_test

import (
	"context"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/repository"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type GetResourceRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
}

func (s *GetResourceRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	pgxMock, err := pgxmock.NewPool()
	s.NoError(err)
	s.mockRedisClient = redisClient
	s.authRepository = repository.New(redisClient, pgxMock, logger)
}

func (s *GetResourceRepositorySuite) SetupTest() {
	s.mockRedisClient.ExpectedCalls = nil
	s.mockRedisClient.Calls = nil
}

func TestGetResourceRepositorySuite(t *testing.T) {
	suite.Run(t, &GetResourceRepositorySuite{})
}

func (s *GetResourceRepositorySuite) TestAuthRepository_GetResource_Success() {
	key := "resource-key"
	value := "resource-value"
	ctx := context.Background()
	s.mockRedisClient.On("Get", mock.Anything, key).Return(value, nil)

	val, err := s.authRepository.GetResource(ctx, key)

	s.NoError(err)
	s.NotEmpty(val)

	s.mockRedisClient.AssertExpectations(s.T())
}

func (s *GetResourceRepositorySuite) TestAuthRepository_GetResource_NotFound() {
	key := "resource-key"
	ctx := context.Background()

	s.mockRedisClient.On("Get", mock.Anything, key).Return("", redis.Nil)

	val, err := s.authRepository.GetResource(ctx, key)

	s.Error(err)
	s.Empty(val)
	s.mockRedisClient.AssertExpectations(s.T())
}
