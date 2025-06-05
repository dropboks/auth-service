package cache

import (
	"context"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

func New(zerolog zerolog.Logger) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:       "localhost:6379",
		ClientName: "auth_service",
		Protocol:   2,
		Password:   "",
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		zerolog.Fatal().Err(err).Msg("failed to connect to redis")
	}
	return client, nil
}
