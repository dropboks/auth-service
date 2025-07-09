package repository

import (
	"context"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/infrastructure/cache"
	"github.com/dropboks/auth-service/internal/infrastructure/db"
	"github.com/dropboks/sharedlib/model"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type (
	AuthRepository interface {
		GetResource(context.Context, string) (string, error)
		SetResource(context.Context, string, string, time.Duration) error
		RemoveResource(context.Context, string) error
		GetUserByUserId(userId string) (*model.User, error)
		GetUserByEmail(email string) (*model.User, error)
	}
	authRepository struct {
		redisClient cache.RedisCache
		logger      zerolog.Logger
		querier     db.Querier
	}
)

func New(r cache.RedisCache, querier db.Querier, logger zerolog.Logger) AuthRepository {
	return &authRepository{
		redisClient: r,
		logger:      logger,
		querier:     querier,
	}
}

func (a *authRepository) GetUserByEmail(email string) (*model.User, error) {
	var user model.User
	query, args, err := sq.Select("id", "full_name", "image", "email", "password", "verified", "two_factor_enabled").
		From("users").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to build query")
		return nil, dto.Err_INTERNAL_FAILED_BUILD_QUERY
	}

	row := a.querier.QueryRow(context.Background(), query, args...)
	err = row.Scan(&user.ID, &user.FullName, &user.Image, &user.Email, &user.Password, &user.Verified, &user.TwoFactorEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.logger.Warn().Str("email", email).Msg("user not found")
			return nil, dto.Err_NOTFOUND_USER_NOT_FOUND
		}
		a.logger.Error().Err(err).Msg("failed to scan user")
		return nil, dto.Err_INTERNAL_FAILED_SCAN_USER
	}
	return &user, nil
}

func (a *authRepository) GetUserByUserId(userId string) (*model.User, error) {
	var user model.User
	query, args, err := sq.Select("id", "full_name", "image", "email", "password", "verified", "two_factor_enabled").
		From("users").
		Where(sq.Eq{"id": userId}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to build query")
		return nil, dto.Err_INTERNAL_FAILED_BUILD_QUERY
	}
	row := a.querier.QueryRow(context.Background(), query, args...)
	err = row.Scan(&user.ID, &user.FullName, &user.Image, &user.Email, &user.Password, &user.Verified, &user.TwoFactorEnabled)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.logger.Warn().Str("id", userId).Msg("user not found")
			return nil, dto.Err_NOTFOUND_USER_NOT_FOUND
		}
		a.logger.Error().Err(err).Msg("failed to scan user")
		return nil, dto.Err_INTERNAL_FAILED_SCAN_USER
	}
	return &user, nil
}

func (a *authRepository) GetResource(c context.Context, key string) (string, error) {
	v, err := a.redisClient.Get(c, key)
	if err != nil {
		if err == redis.Nil {
			return "", dto.Err_NOTFOUND_KEY_NOTFOUND
		}
		return "", dto.Err_INTERNAL_GET_RESOURCE
	}
	return v, nil
}

func (a *authRepository) RemoveResource(c context.Context, key string) error {
	if err := a.redisClient.Delete(c, key); err != nil {
		return dto.Err_INTERNAL_DELETE_RESOURCE
	}
	return nil
}

func (a *authRepository) SetResource(c context.Context, key, value string, duration time.Duration) error {
	err := a.redisClient.Set(c, key, value, duration)
	if err != nil {
		return dto.Err_INTERNAL_SET_RESOURCE
	}
	return nil
}
