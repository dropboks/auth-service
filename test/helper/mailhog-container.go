package helper

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type MailhogContainer struct {
	testcontainers.Container
	Host string
	Port string
}

func StartMailhogContainer(ctx context.Context, networkName string) (*MailhogContainer, error) {
	req := testcontainers.ContainerRequest{
		Name:         "mailhog",
		Image:        "mailhog/mailhog:v1.0.1",
		ExposedPorts: []string{"1025:1025/tcp", "8025:8025/tcp"},
		Networks:     []string{networkName},
		WaitingFor:   wait.ForListeningPort("1025/tcp"),
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
		return nil, err
	}

	port, err := container.MappedPort(ctx, "1025")
	if err != nil {
		return nil, err
	}

	return &MailhogContainer{
		Container: container,
		Host:      host,
		Port:      port.Port(),
	}, nil
}

func (m *MailhogContainer) SMTPAddr() string {
	return fmt.Sprintf("%s:%s", m.Host, m.Port)
}

func (m *MailhogContainer) Terminate(ctx context.Context) error {
	if m.Container != nil {
		return m.Container.Terminate(ctx)
	}
	return nil
}
