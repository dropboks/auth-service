package helper

import (
	"context"
	"fmt"

	"github.com/spf13/viper"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type NatsContainer struct {
	Container testcontainers.Container
	URI       string
}

func StartNatsContainer(ctx context.Context) (*NatsContainer, error) {
	req := testcontainers.ContainerRequest{
		Name:         "nats",
		Image:        "nats:2.11.6",
		ExposedPorts: []string{"4221:4221/tcp"},
		WaitingFor:   wait.ForLog("Server is ready"),
		Env: map[string]string{
			"NATS_USER":     viper.GetString("minio.credential.user"),
			"NATS_PASSWORD": viper.GetString("minio.credential.password"),
		},
		Cmd: []string{
			"-c", "/etc/nats/nats.conf",
			"--name", "nats",
			"-p", "4221",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "../mocks/nats/nats-server.conf",
				ContainerFilePath: "/etc/nats/nats.conf",
				FileMode:          0644,
			},
		},
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

	port, err := container.MappedPort(ctx, "4221")
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}

	uri := fmt.Sprintf("nats://%s:%s", host, port.Port())
	return &NatsContainer{
		Container: container,
		URI:       uri,
	}, nil
}

func (n *NatsContainer) Terminate(ctx context.Context) error {
	if n.Container != nil {
		return n.Container.Terminate(ctx)
	}
	return nil
}
