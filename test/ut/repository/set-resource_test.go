package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/dropboks/auth-service/internal/domain/repository"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type SetResourceRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
}

func (s *SetResourceRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	s.mockRedisClient = redisClient
	s.authRepository = repository.New(redisClient, logger)
}

func (s *SetResourceRepositorySuite) SetupTest() {
	s.mockRedisClient.ExpectedCalls = nil
	s.mockRedisClient.Calls = nil
}

func TestSetResourceRepositorySuite(t *testing.T) {
	suite.Run(t, &SetResourceRepositorySuite{})
}

func (s *SetResourceRepositorySuite) TestAuthRepository_SetResource_Success() {
	key := "resource-key"
	value := "resource-value"
	dur := 1 * time.Millisecond
	ctx := context.Background()

	s.mockRedisClient.On("Set", mock.Anything, key, value, dur).Return(nil)

	err := s.authRepository.SetResource(ctx, key, value, dur)

	assert.NoError(s.T(), err)

	s.mockRedisClient.AssertExpectations(s.T())
}
