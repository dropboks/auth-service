package helper

import (
	"context"
	"fmt"

	"github.com/spf13/viper"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type RedisContainer struct {
	testcontainers.Container
	URI string
}

func StartRedisContainer(ctx context.Context) (*RedisContainer, error) {

	req := testcontainers.ContainerRequest{
		Name:         "redis",
		Image:        "redis:7.2",
		ExposedPorts: []string{"6379:6379/tcp"},
		Env: map[string]string{
			"REDIS_PASSWORD": viper.GetString("redis.password"),
		},
		Cmd:        []string{"redis-server", "--requirepass", viper.GetString("redis.password")},
		WaitingFor: wait.ForListeningPort("6379/tcp"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}
	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}

	uri := fmt.Sprintf("%s:%s", host, port.Port())
	return &RedisContainer{Container: container, URI: uri}, nil
}

func (r *RedisContainer) Terminate(ctx context.Context) error {
	if r.Container != nil {
		return r.Container.Terminate(ctx)
	}
	return nil
}
