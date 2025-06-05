package repository

import (
	"context"
	"time"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/infrastructure/cache"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type (
	AuthRepository interface {
		SetAccessToken(context.Context, string, string) error
		RemoveAccessToken(context.Context, string) error
		CheckAccessToken(context.Context, string) error
	}
	authRepository struct {
		redisClient cache.RedisCache
		logger      zerolog.Logger
	}
)

func New(r cache.RedisCache, logger zerolog.Logger) AuthRepository {
	return &authRepository{
		redisClient: r,
		logger:      logger,
	}
}

func (a *authRepository) CheckAccessToken(c context.Context, key string) error {
	_, err := a.redisClient.Get(c, key)
	if err != nil {
		if err == redis.Nil {
			return dto.Err_NOTFOUND_KEY_NOTFOUND
		}
		return dto.Err_INTERNAL_GET_TOKEN
	}
	return nil
}

func (a *authRepository) RemoveAccessToken(c context.Context, key string) error {
	if err := a.redisClient.Delete(c, key); err != nil {
		return dto.Err_INTERNAL_DELETE_TOKEN
	}
	return nil
}

func (a *authRepository) SetAccessToken(c context.Context, key, value string) error {
	err := a.redisClient.Set(c, key, value, 1*time.Hour)
	if err != nil {
		return err
	}
	return nil
}
