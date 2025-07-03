package helper

import (
	"context"
	"log"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
)

func StartNetwork(ctx context.Context) *testcontainers.DockerNetwork {
	sharedNetwork, err := network.New(ctx)
	if err != nil {
		log.Fatal("failed create network")
	}
	return sharedNetwork
}
