package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dropboks/auth-service/internal/domain/handler"
	"github.com/dropboks/auth-service/internal/infrastructure/grpc"
	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"go.uber.org/dig"
)

type Server struct {
	Container   *dig.Container
	ServerReady chan bool
}

func (s *Server) Run() {
	err := s.Container.Invoke(
		func(
			logger zerolog.Logger,
			router *gin.Engine,
			grpcClientManager *grpc.GRPCClientManager,
			redis *redis.Client,
			nc *nats.Conn,
			ah handler.AuthHandler,
		) {
			defer grpcClientManager.CloseAllConnections()
			defer redis.Close()
			defer nc.Drain()

			handler.AuthRoutes(router, ah)
			srv := &http.Server{
				Addr:    ":" + viper.GetString("app.http.port"),
				Handler: router,
			}
			logger.Info().Msgf("HTTP Server Starting in port %s", viper.GetString("app.http.port"))

			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal().Err(err).Msg("Failed to listen and server http server")
				}
			}()

			if s.ServerReady != nil {
				s.ServerReady <- true
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit
			logger.Info().Msg("Shutting down server...")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				logger.Fatal().Err(err).Msg("Server forced to shutdown")
			}
			logger.Info().Msg("Server exiting...")
		})
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
}
