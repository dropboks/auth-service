package helper

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
)

type FileServiceContainer struct {
	Container testcontainers.Container
}

func StartFileServiceContainer(ctx context.Context) (*FileServiceContainer, error) {
	req := testcontainers.ContainerRequest{
		Name:         "file_service",
		Image:        "file_service:test",
		ExposedPorts: []string{"50552:50552/tcp"},
		Env:          map[string]string{"ENV": "test-dependence"},
		Cmd:          []string{"/file_service"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &FileServiceContainer{
		Container: container,
	}, nil
}
