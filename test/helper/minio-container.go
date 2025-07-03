package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/viper"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type MinioContainer struct {
	testcontainers.Container
	Endpoint  string
	AccessKey string
	SecretKey string
}

func StartMinioContainer(ctx context.Context) (*MinioContainer, error) {
	var (
		minioImage  = "minio/minio:RELEASE.2025-05-24T17-08-30Z-cpuv1"
		accessKey   = viper.GetString("minio.credential.user")
		secretKey   = viper.GetString("minio.credential.password")
		exposedPort = "9000:9000/tcp"
	)
	req := testcontainers.ContainerRequest{
		Name:         "minio",
		Image:        minioImage,
		ExposedPorts: []string{exposedPort},
		Env: map[string]string{
			"MINIO_ROOT_USER":     accessKey,
			"MINIO_ROOT_PASSWORD": secretKey,
		},
		Cmd:        []string{"server", "/data"},
		WaitingFor: wait.ForLog("API:").WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start minio container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}
	port, err := container.MappedPort(ctx, "9000")
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	return &MinioContainer{
		Container: container,
		Endpoint:  endpoint,
		AccessKey: accessKey,
		SecretKey: secretKey,
	}, nil
}

func (mc *MinioContainer) Terminate(ctx context.Context) error {
	if mc.Container != nil {
		return mc.Container.Terminate(ctx)
	}
	return nil
}
