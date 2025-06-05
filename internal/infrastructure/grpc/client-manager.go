package grpc

import (
	"log"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCClientManager struct {
	connections map[string]*grpc.ClientConn
	mu          sync.Mutex
}

func NewGRPCClientManager() *GRPCClientManager {
	return &GRPCClientManager{
		connections: make(map[string]*grpc.ClientConn),
	}
}

func (m *GRPCClientManager) GetConnection(address string) *grpc.ClientConn {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, exists := m.connections[address]; exists {
		return conn
	}

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server at %s: %v", address, err)
	}
	m.connections[address] = conn
	return conn
}

func (m *GRPCClientManager) CloseAllConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for address, conn := range m.connections {
		conn.Close()
		delete(m.connections, address)
	}
}
