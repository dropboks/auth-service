package cache

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func New(zerolog zerolog.Logger) (*redis.Client, error) {
	addr := fmt.Sprintf("%s:%s", viper.GetString("redis.address"), viper.GetString("redis.port"))
	client := redis.NewClient(&redis.Options{
		Addr:       addr,
		ClientName: viper.GetString("redis.client_name"),
		Protocol:   2,
		Password:   viper.GetString("redis.password"),
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		zerolog.Fatal().Err(err).Msg("failed to connect to redis")
	}
	return client, nil
}
