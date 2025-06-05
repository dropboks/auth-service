package bootstrap

import (
	"github.com/dropboks/auth-service/cmd/di"
	"github.com/dropboks/auth-service/config/env"
	"go.uber.org/dig"
)

func Run() *dig.Container {
	env.Load()
	container := di.BuildContainer()
	return container
}
