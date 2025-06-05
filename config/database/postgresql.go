package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func New(logger zerolog.Logger) *pgxpool.Pool {
	host := viper.GetString("database.host")
	user := viper.GetString("database.user")
	password := viper.GetString("database.password")
	port := viper.GetString("database.port")
	dbname := viper.GetString("database.name")
	sslmode := viper.GetString("database.sslmode")
	dsn := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s", user, password, host, port, dbname, sslmode)
	if dsn == "" {
		logger.Fatal().Msg("Database configuration is not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("Database configuration is not set")
	}
	return pool
}
