package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/viper"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PostgresContainer struct {
	Container testcontainers.Container
	Host      string
	Port      string
	User      string
	Password  string
	DBName    string
}

func StartPostgresContainer(ctx context.Context, sharedNetwork, name, port string) (*PostgresContainer, error) {
	ports := fmt.Sprintf("%s:5432/tcp", port)
	req := testcontainers.ContainerRequest{
		Name:         name,
		Image:        "postgres:17.5-alpine3.22",
		ExposedPorts: []string{ports},
		Env: map[string]string{
			"POSTGRES_DB":       viper.GetString("database.name"),
			"POSTGRES_USER":     viper.GetString("database.user"),
			"POSTGRES_PASSWORD": viper.GetString("database.password"),
		},
		Networks: []string{sharedNetwork},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(5 * time.Second),
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "../mocks/db/init-db.sql",
				ContainerFilePath: "/docker-entrypoint-initdb.d/init-db.sql",
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

	mappedPort, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		return nil, err
	}

	return &PostgresContainer{
		Container: nil,
		Host:      host,
		Port:      mappedPort.Port(),
		User:      viper.GetString("database.user"),
		Password:  viper.GetString("database.password"),
		DBName:    viper.GetString("database.name"),
	}, nil
}

func (p *PostgresContainer) GetDSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Password, p.DBName)
}

func (p *PostgresContainer) Terminate(ctx context.Context) error {
	if p.Container != nil {
		return p.Container.Terminate(ctx)
	}
	return nil
}
