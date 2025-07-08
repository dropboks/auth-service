package server

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dropboks/auth-service/internal/domain/handler"
	"github.com/dropboks/auth-service/internal/infrastructure/grpc"
	event "github.com/dropboks/event-bus-client/pkg/event/user"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
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
			pgx *pgxpool.Pool,
			ue event.UserEventConsumer,
			js jetstream.JetStream,
		) {
			defer grpcClientManager.CloseAllConnections()
			defer redis.Close()
			defer nc.Drain()
			defer pgx.Close()

			router.Use(gin.Recovery())
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

			// init consumer here
			go ue.StartConsume()

			if s.ServerReady != nil {
				for range 50 {
					conn, err := net.DialTimeout("tcp", ":"+viper.GetString("app.http.port"), 100*time.Millisecond)
					if err == nil {
						conn.Close()
						s.ServerReady <- true
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGTERM)

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
