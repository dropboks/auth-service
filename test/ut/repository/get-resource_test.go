package repository_test

import (
	"context"
	"testing"

	"github.com/dropboks/auth-service/internal/domain/repository"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
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
	s.mockRedisClient = redisClient
	s.authRepository = repository.New(redisClient, logger)
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

	assert.NotEmpty(s.T(), val)
	assert.NoError(s.T(), err)

	s.mockRedisClient.AssertExpectations(s.T())
}

func (s *GetResourceRepositorySuite) TestAuthRepository_GetResource_NotFound() {
	key := "resource-key"
	ctx := context.Background()

	s.mockRedisClient.On("Get", mock.Anything, key).Return("", redis.Nil)

	val, err := s.authRepository.GetResource(ctx, key)

	assert.Empty(s.T(), val)
	assert.Error(s.T(), err)

	s.mockRedisClient.AssertExpectations(s.T())
}
