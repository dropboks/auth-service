package helper

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
)

type UserServiceContainer struct {
	Container testcontainers.Container
}

func StartUserServiceContainer(ctx context.Context) (*UserServiceContainer, error) {
	req := testcontainers.ContainerRequest{
		Name:         "user_service",
		Image:        "user_service:test",
		ExposedPorts: []string{"50551:50551/tcp"},
		Env:          map[string]string{"ENV": "test-dependence"},
		Cmd:          []string{"/user_service"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &UserServiceContainer{
		Container: container,
	}, nil
}
