package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/dropboks/auth-service/cmd/bootstrap"
	"github.com/dropboks/auth-service/cmd/server"
	"github.com/spf13/viper"
)

func main() {
	container := bootstrap.Run()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServerReady := make(chan bool)
	httpServerDone := make(chan struct{})
	httpServer := &server.Server{
		Container:   container,
		ServerReady: httpServerReady,
		Address:     ":" + viper.GetString("app.http.port"),
	}
	go func() {
		httpServer.Run(ctx)
		close(httpServerDone)
	}()

	<-httpServerReady

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGTERM)

	<-sig
	cancel()
}
