package helper

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
)

type NotificationServiceContainer struct {
	Container testcontainers.Container
}

func StartNotificationServiceContainer(ctx context.Context, sharedNetwork string) (*NotificationServiceContainer, error) {
	req := testcontainers.ContainerRequest{
		Name:     "notification_service",
		Image:    "notification_service:v0.0.1",
		Env:      map[string]string{"ENV": "test-dependence"},
		Networks: []string{sharedNetwork},
		Cmd:      []string{"/notification_service"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &NotificationServiceContainer{
		Container: container,
	}, nil
}

func (f *NotificationServiceContainer) Terminate(ctx context.Context) error {
	if f.Container != nil {
		return f.Container.Terminate(ctx)
	}
	return nil
}
